#!/usr/bin/env python3
"""Canonical record schema + the domain allowlist (flowchart: Pydantic Validation).

Every record that survives the source mapper is validated against
:class:`CanonicalRecord` — a Pydantic v2 model with ``field_validator`` rules and
a closed domain allowlist. Invalid records raise ``pydantic.ValidationError``
(v2 error types) and are routed to the rejected sink by the pipeline.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ------------------------------------------------------------- domain allowlist
# The 12 canonical cybersecurity domains the corpus is organised around (the
# flowchart's "12-domain allowlist"). ``Quantum`` is a later 13th track; it is
# accepted too so post-quantum sources are not rejected. Edit here to add a
# domain — validation derives straight from this set.
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
EXTRA_DOMAINS: tuple[str, ...] = ("Quantum",)
ALLOWED_DOMAINS: frozenset[str] = frozenset(CANONICAL_DOMAINS + EXTRA_DOMAINS)

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

MIN_TEXT_CHARS = 20            # canonical text floor (cleaning already enforces 50)


def normalize_domain(value: str) -> str:
    """Map a raw domain string (often a folder name) onto a canonical domain.

    Tries an exact match, then a case-insensitive alias, then a case-insensitive
    match against the allowlist. Raises ``ValueError`` if nothing fits so the
    Pydantic validator can reject the record.
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


# --------------------------------------------------------------- canonical model
class CanonicalRecord(BaseModel):
    """The normalized record schema handed to dedup and, ultimately, annotation.

    Original structured columns that are not part of the canonical shape are
    preserved under ``meta`` so nothing is lost; ``text`` is the corpus payload.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    # Human-readable run reference (source + positional counter), e.g.
    # "india-it-act-2000:00000042". The pipeline also stamps each dataset.jsonl
    # row with a sequential `record_id` (rec_000000001, … — the annotation-team
    # handoff label) and a `content_hash` (the stable content fingerprint; use
    # this to re-link if the data is regenerated, since rec_ ids can shift).
    id: str = Field(..., description="human-readable positional id; stable anchor is content_hash")
    domain: str = Field(..., description="one of the canonical domains")
    source: str = Field(..., description="human-readable source name")
    text: str = Field(..., description="normalized natural-language payload")
    url: str | None = None
    license: str | None = None
    text_field: str | None = Field(
        default=None, description="original column that became `text`")
    meta: dict[str, Any] = Field(default_factory=dict)

    @field_validator("domain")
    @classmethod
    def _check_domain(cls, v: str) -> str:
        return normalize_domain(v)

    @field_validator("text")
    @classmethod
    def _check_text(cls, v: str) -> str:
        v = v.strip()
        if len(v) < MIN_TEXT_CHARS:
            raise ValueError(f"text shorter than {MIN_TEXT_CHARS} chars")
        return v

    @field_validator("source")
    @classmethod
    def _check_source(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("source is empty")
        return v.strip()
