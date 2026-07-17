#!/usr/bin/env python3
"""Heuristic security-hazard scanner for raw ingested records.

A cybersecurity corpus legitimately contains exploit code, shellcode snippets,
and embedded payloads — so this scanner **reports and never drops**.

What it does with a finding, precisely, because this docstring used to overstate
it: :func:`scan_record` returns findings, :func:`scan_source_sample` samples a
source, and ``light_eda.assess_source`` counts them by type into the ingest
report's ``flags.security_hazards``, each with its worst severity. That is all.
Nothing is quarantined and nothing is blocked: the gate's reject paths are the
volume/quality checks, and a hazard has never influenced them.

(This docstring previously claimed flagged records were "diverted to
``data/flagged/`` with a ``_stage=hazard`` annotation so the Data Annotation Team
can review them". No code ever did that — ``data/flagged/`` is written only by
the *cleaning* stage's anomaly path, always with ``stage="anomaly"``. Describing
a quarantine that does not exist is worse than describing no quarantine, because
a reader plans around it.)

Scope: text fields of already-parsed records. Binaries and archive members are a
different question, and :mod:`.binscan` answers that one.

Checks:
    1. Embedded ``<script>`` / ``<iframe>`` / ``javascript:`` in text fields
    2. Suspiciously long base64-encoded strings (>500 chars)
    3. Shell command-injection patterns in structured fields
    4. URLs matching known malware-distribution TLDs / patterns

Public API:
    scan_record(rec) -> list[dict]   # each dict = one hazard finding
"""

from __future__ import annotations

import re

# ── Patterns ─────────────────────────────────────────────────────────────────

# 1. Embedded active content (HTML/JS injection)
_SCRIPT_RE = re.compile(
    r"<\s*(?:script|iframe|object|embed|applet)\b[^>]*>",
    re.IGNORECASE,
)
_JS_URI_RE = re.compile(r"javascript\s*:", re.IGNORECASE)

# 2. Long base64 blobs (potential encoded payloads)
# Match >=500 chars of contiguous base64 alphabet (letters, digits, +, /, =)
_BASE64_RE = re.compile(r"[A-Za-z0-9+/=]{500,}")

# 3. Shell command-injection patterns in structured (non-text) fields
_SHELL_RE = re.compile(
    r"(?:"
    r"\$\(.*?\)"               # $(cmd) subshell
    r"|`[^`]{2,}`"             # `cmd` backtick subshell
    r"|;\s*(?:rm|curl|wget|chmod|bash|sh|python|perl|nc|ncat)\b"
    r"|&&\s*(?:rm|curl|wget|chmod|bash|sh|python|perl|nc|ncat)\b"
    r"|\|\s*(?:bash|sh|python|perl)\b"
    r")",
    re.IGNORECASE,
)

# 4. Suspicious URL patterns (known malware distribution / C2 indicators)
_SUSPICIOUS_URL_RE = re.compile(
    r"(?:https?://)"
    r"(?:"
    r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"   # bare IP URLs
    r"|.*?\.(?:tk|ml|ga|cf|gq|top|xyz|buzz|club|work|date|racing|download)\b"  # high-abuse TLDs
    r"|.*?pastebin\.com/raw/"                              # raw pastebin (payload hosting)
    r"|.*?transfer\.sh/"                                   # ephemeral file sharing
    r")",
    re.IGNORECASE,
)

# Fields that are "structured" (not prose) — shell injection in these is riskier
_STRUCTURED_FIELDS = frozenset({
    "url", "source_url", "link", "command", "cmd", "script",
    "filename", "path", "file_path", "download_url",
})


def _snippet(text: str, match: re.Match, context: int = 60) -> str:
    """Return a short context snippet around the match."""
    start = max(0, match.start() - context)
    end = min(len(text), match.end() + context)
    return text[start:end]


def scan_record(rec: dict) -> list[dict]:
    """Scan a single raw record for security hazards.

    Returns a list of hazard findings, each with:
        ``{type, field, snippet, severity}``

    Severity levels:
        ``"info"``    — common in cybersecurity text, mostly benign
        ``"warning"`` — unusual for training data, worth a human look
    """
    hazards: list[dict] = []

    for field, value in rec.items():
        if field.startswith("_") or not isinstance(value, str) or not value:
            continue

        is_structured = field in _STRUCTURED_FIELDS
        text = value

        # 1. Embedded active content
        for m in _SCRIPT_RE.finditer(text):
            hazards.append({
                "type": "embedded_active_content",
                "field": field,
                "snippet": _snippet(text, m),
                "severity": "warning",
            })

        for m in _JS_URI_RE.finditer(text):
            hazards.append({
                "type": "javascript_uri",
                "field": field,
                "snippet": _snippet(text, m),
                "severity": "warning",
            })

        # 2. Long base64 blobs
        for m in _BASE64_RE.finditer(text):
            hazards.append({
                "type": "base64_payload",
                "field": field,
                "snippet": f"[{len(m.group())} chars of base64]",
                "severity": "info",
            })

        # 3. Shell injection in structured fields
        if is_structured:
            for m in _SHELL_RE.finditer(text):
                hazards.append({
                    "type": "shell_injection",
                    "field": field,
                    "snippet": _snippet(text, m),
                    "severity": "warning",
                })

        # 4. Suspicious URLs
        for m in _SUSPICIOUS_URL_RE.finditer(text):
            hazards.append({
                "type": "suspicious_url",
                "field": field,
                "snippet": _snippet(text, m, context=80),
                "severity": "info",
            })

    return hazards


def scan_source_sample(records: list[dict], *, max_records: int = 200) -> list[dict]:
    """Scan a sample of records from a source and aggregate hazard findings.

    Returns a flat list of all hazards found, each annotated with the record
    index within the sample.
    """
    all_hazards: list[dict] = []
    for i, rec in enumerate(records[:max_records]):
        for h in scan_record(rec):
            h["record_index"] = i
            all_hazards.append(h)
    return all_hazards
