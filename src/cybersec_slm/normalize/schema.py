#!/usr/bin/env python3
"""Canonical record schema — the 22-field training-dataset contract.

Every record that survives the source mapper is validated against
:class:`CanonicalRecord` (Pydantic v2). The schema is the handoff contract with
the downstream labeling + annotation pipelines, so it is emitted *in full*: the
collection pipeline fills every field it can know, and stamps explicit
placeholders for the fields owned downstream —

  * snorkel weak-supervision labels (``domain_label`` / ``subdomain_label``)
    -> ``-1`` (ABSTAIN), and
  * human annotation (``safe_unsafe`` / ``confidence`` / ``instruction`` /
    ``reviewed_by``) -> ``None``.

``domain_name`` / ``subdomain_name`` are *not* placeholders — they are derived
from the pipeline's existing 12-domain routing (see :func:`resolve_domain`).

Invalid records raise ``pydantic.ValidationError`` and are routed to the
metadata-only rejected sink by the pipeline.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ----------------------------------------------------------- domain allowlist --
# The 12 canonical cybersecurity domains the corpus is organised around.
CANONICAL_DOMAINS: tuple[str, ...] = (
    "Application Security",
    "Cloud Security",
    "Cryptography",
    "Data Security and Privacy",
    "Governance, Risk and Compliance",
    "Identity Access and Management",
    "Incident Response and Forensics",
    "Malware Analysis",
    "Network Security",
    "Penetration Testing and Vulnerability Management",
    "Security Operations",
    "Threat Intelligence",
)
# A later 13th track. Post-quantum sources map onto the CRYPTOGRAPHY subdomain
# but carry the QUANTUM_SEC top-level domain (per the schema's domain note).
QUANTUM_DOMAIN = "Quantum"
ALLOWED_DOMAINS: frozenset[str] = frozenset(CANONICAL_DOMAINS + (QUANTUM_DOMAIN,))

# Folder/spelling variants seen in the wild -> canonical domain. Keeps real data
# from being rejected over a directory typo (e.g. "Forsenics").
DOMAIN_ALIASES: dict[str, str] = {
    "incident response and forsenics": "Incident Response and Forensics",
    "incident response and forensics": "Incident Response and Forensics",
    "governance risk and compliance": "Governance, Risk and Compliance",
    "iam": "Identity Access and Management",
    "grc": "Governance, Risk and Compliance",
    "appsec": "Application Security",
}

# ----------------------------------------------- subdomain enum (schema names) -
# The 12 schema `subdomain_name` values, in the canonical 0..11 order that the
# downstream snorkel_subdomain.py LabelModel must align to. The integer
# `subdomain_label` we emit is always -1 (ABSTAIN) — this ordering only fixes the
# name<->index contract for when labels are later assigned downstream.
SUBDOMAIN_NAMES: tuple[str, ...] = (
    "APPLICATION",            # 0  Application Security
    "CLOUD",                  # 1  Cloud Security
    "CRYPTOGRAPHY",           # 2  Cryptography
    "DATA_PRIVACY",           # 3  Data Security and Privacy
    "GRC",                    # 4  Governance, Risk and Compliance
    "IAM",                    # 5  Identity Access and Management
    "INCIDENT_RESPONSE",      # 6  Incident Response and Forensics
    "MALWARE_ANALYSIS",       # 7  Malware Analysis
    "NETWORK",                # 8  Network Security
    "PENTEST",                # 9  Penetration Testing and Vulnerability Management
    "SECOPS",                 # 10 Security Operations
    "THREAT_INTELLIGENCE",    # 11 Threat Intelligence
)
CANONICAL_TO_SUBDOMAIN: dict[str, str] = dict(
    zip(CANONICAL_DOMAINS, SUBDOMAIN_NAMES, strict=True))
ALLOWED_SUBDOMAINS: frozenset[str] = frozenset(SUBDOMAIN_NAMES)

# domain_name (top-level) enum + integer codes (the schema's domain_label space).
DOMAIN_NAMES: frozenset[str] = frozenset({"CYBERSEC", "QUANTUM_SEC"})

# Record-type enum (schema examples: cve / article / log). Open-ish but closed to
# a known set so a mapper bug surfaces as a reject rather than silent drift.
RECORD_TYPES: frozenset[str] = frozenset(
    {"cve", "article", "log", "advisory", "playbook", "doc", "code", "other"})

# Placeholders for downstream-owned fields.
ABSTAIN = -1
MIN_TEXT_CHARS = 20            # canonical text floor (cleaning already enforces 50)


def normalize_domain(value: str) -> str:
    """Map a raw domain string (often a folder name) onto a canonical domain.

    Exact match, then case-insensitive alias, then case-insensitive allowlist
    match. Raises ``ValueError`` if nothing fits so the caller can reject.
    """
    if value in ALLOWED_DOMAINS:
        return value
    key = " ".join(str(value).strip().lower().split())
    if key in DOMAIN_ALIASES:
        return DOMAIN_ALIASES[key]
    for d in ALLOWED_DOMAINS:
        if d.lower() == key:
            return d
    raise ValueError(f"domain not in allowlist: {value!r}")


def resolve_domain(value: str) -> tuple[str, str]:
    """Raw domain -> ``(domain_name, subdomain_name)`` schema enum values.

    Quantum -> (QUANTUM_SEC, CRYPTOGRAPHY); the 12 cybersecurity domains ->
    (CYBERSEC, <their subdomain>). Raises ``ValueError`` for an unknown domain.
    """
    canonical = normalize_domain(value)
    if canonical == QUANTUM_DOMAIN:
        return "QUANTUM_SEC", "CRYPTOGRAPHY"
    return "CYBERSEC", CANONICAL_TO_SUBDOMAIN[canonical]


# --------------------------------------------------------------- canonical model
class CanonicalRecord(BaseModel):
    """The 22-field normalized record handed to dedup and, ultimately, training."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    # 1) Identity
    id: str = Field(..., description="globally unique record id (uuid4)")
    content_hash: str = Field(..., description="sha256 hex of the text field")

    # 2) Content
    text: str = Field(..., description="cleaned natural-language payload")

    # 3) Provenance
    source: str = Field(..., description="dataset / collection source name")
    source_url: str | None = Field(default=None, description="original URL if scraped")
    license: str = Field(default="", description="SPDX (or best-effort) license id")
    origin_format: str = Field(default="jsonl", description="original file format")

    # 4) Auto-computed
    lang: str = Field(default="en", description="ISO 639-1 language code")
    token_count: int = Field(default=0, ge=0)
    char_count: int = Field(default=0, ge=0)

    # 5) Pipeline metadata
    pipeline_version: str = Field(..., description="semver of the pipeline")
    collected_at: str = Field(..., description="ISO 8601 UTC collection timestamp")

    # 6) Pipeline labels (names derived here; integer labels are downstream)
    source_file: str = Field(..., description="routing key for the source")
    record_type: str = Field(default="article")
    domain_label: int = Field(default=ABSTAIN, description="downstream snorkel; -1 ABSTAIN")
    domain_name: str = Field(..., description="CYBERSEC or QUANTUM_SEC")
    subdomain_label: int = Field(default=ABSTAIN, description="downstream snorkel; -1 ABSTAIN")
    subdomain_name: str = Field(..., description="one of the 12 subdomain names")

    # 7) Annotation (downstream-owned; null placeholders)
    safe_unsafe: str | None = Field(default=None, description="SAFE / UNSAFE")
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    instruction: str | None = None
    reviewed_by: str | None = None

    # -- validators ----------------------------------------------------------
    @field_validator("text")
    @classmethod
    def _check_text(cls, v: str) -> str:
        v = v.strip()
        if len(v) < MIN_TEXT_CHARS:
            raise ValueError(f"text shorter than {MIN_TEXT_CHARS} chars")
        return v

    @field_validator("source", "source_file")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must not be empty")
        return v.strip()

    @field_validator("content_hash")
    @classmethod
    def _check_hash(cls, v: str) -> str:
        v = v.strip().lower()
        if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
            raise ValueError("content_hash must be a 64-char sha256 hex digest")
        return v

    @field_validator("domain_name")
    @classmethod
    def _check_domain_name(cls, v: str) -> str:
        if v not in DOMAIN_NAMES:
            raise ValueError(f"domain_name not in {sorted(DOMAIN_NAMES)}")
        return v

    @field_validator("subdomain_name")
    @classmethod
    def _check_subdomain(cls, v: str) -> str:
        if v not in ALLOWED_SUBDOMAINS:
            raise ValueError(f"subdomain_name not in the {len(SUBDOMAIN_NAMES)} allowed")
        return v

    @field_validator("record_type")
    @classmethod
    def _check_record_type(cls, v: str) -> str:
        v = (v or "other").strip().lower()
        return v if v in RECORD_TYPES else "other"

    @field_validator("domain_label", "subdomain_label")
    @classmethod
    def _check_label(cls, v: int) -> int:
        if v < ABSTAIN:
            raise ValueError("label must be >= -1")
        return v

    @field_validator("safe_unsafe")
    @classmethod
    def _check_safe(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().upper()
        if v not in ("SAFE", "UNSAFE"):
            raise ValueError("safe_unsafe must be SAFE, UNSAFE, or null")
        return v
