#!/usr/bin/env python3
"""Record enrichment — assemble the full canonical record from a mapper's output.

A mapper produces only text + provenance (it knows the record shape); everything
else in the 22-field contract is computed here: a fresh ``id``, the
``content_hash``, the auto-computed ``lang`` / ``token_count`` / ``char_count``,
pipeline metadata, the resolved ``domain_name`` / ``subdomain_name``, and the
downstream-owned placeholder fields. :func:`build_record` returns a plain dict
ready to validate against :class:`~cybersec_slm.normalize.schema.CanonicalRecord`.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import UTC, datetime
from functools import lru_cache

from ..core import try_import
from .schema import ABSTAIN, resolve_domain

_WORD = re.compile(r"\w+")


@lru_cache(maxsize=1)
def pipeline_version() -> str:
    """Installed package version, falling back to the pyproject default."""
    try:
        from importlib.metadata import version
        return version("cybersec-slm-data-pipeline")
    except Exception:
        return "0.1.0"


@lru_cache(maxsize=1)
def _langdetect():
    ld = try_import("langdetect")
    if ld is not None:
        # deterministic detection across runs
        try:
            ld.DetectorFactory.seed = 0
        except Exception:
            pass
    return ld


def detect_lang(text: str) -> str:
    """ISO 639-1 code via langdetect; defaults to ``en`` when unavailable/uncertain.

    By normalize time the cleaning stage has already translated non-English text
    into English, so the common case is genuinely ``en``.
    """
    ld = _langdetect()
    sample = (text or "")[:1000].strip()
    if ld is None or not sample:
        return "en"
    try:
        return ld.detect(sample)
    except Exception:
        return "en"


def content_hash(text: str) -> str:
    """sha256 hex of the (exact) text field — the schema's content_hash."""
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def token_count(text: str) -> int:
    return len(_WORD.findall(text or ""))


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


# Keyword -> record_type, checked in order against "source_file source" text.
_RECORD_TYPE_RULES = (
    ("cve", ("nvd", "cve", "kev")),
    ("log", ("cloudtrail", "syslog", "auth-log", "raw_log", " log")),
    ("advisory", ("att&ck", "attack", "capec", "cwe", "mitre")),
    ("playbook", ("playbook", "runbook")),
    ("doc", ("nist", "sp800", "sp-800", "fips", "-act-", "gdpr", "dpdp", "iso-")),
)


def classify_record_type(source_file: str, source: str = "") -> str:
    """Best-effort record_type from the source identifiers (schema: cve/log/...)."""
    hay = f" {source_file} {source} ".lower()
    for rtype, needles in _RECORD_TYPE_RULES:
        if any(n in hay for n in needles):
            return rtype
    return "article"


def build_record(mapped: dict) -> dict:
    """Mapper output -> full canonical-record dict (pre-validation).

    ``mapped`` carries: text, source, source_url, license, origin_format,
    source_file, raw_domain, and optionally record_type. Raises ``ValueError``
    (via :func:`resolve_domain`) for an unknown domain so the caller can reject.
    """
    text = mapped["text"]
    source_file = mapped["source_file"]
    source = mapped.get("source") or source_file
    domain_name, subdomain_name = resolve_domain(mapped["raw_domain"])
    return {
        # identity
        "id": str(uuid.uuid4()),
        "content_hash": content_hash(text),
        # content
        "text": text,
        # provenance
        "source": source,
        "source_url": mapped.get("source_url"),
        "license": mapped.get("license") or "",
        "origin_format": mapped.get("origin_format") or "jsonl",
        # auto-computed
        "lang": detect_lang(text),
        "token_count": token_count(text),
        "char_count": len(text),
        # pipeline metadata
        "pipeline_version": pipeline_version(),
        "collected_at": _now_iso(),
        # labels (names derived; integer labels owned downstream)
        "source_file": source_file,
        "record_type": mapped.get("record_type") or classify_record_type(source_file, source),
        "domain_label": ABSTAIN,
        "domain_name": domain_name,
        "subdomain_label": ABSTAIN,
        "subdomain_name": subdomain_name,
        # annotation (downstream-owned placeholders)
        "safe_unsafe": None,
        "confidence": None,
        "instruction": None,
        "reviewed_by": None,
    }
