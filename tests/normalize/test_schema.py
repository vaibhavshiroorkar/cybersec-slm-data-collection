"""Tests for the 22-field CanonicalRecord schema + domain resolution."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from cybersec_slm.normalize.schema import (
    CANONICAL_DOMAINS,
    DOMAIN_NAMES,
    SUBDOMAIN_NAMES,
    CanonicalRecord,
    normalize_domain,
    resolve_domain,
)
from cybersec_slm.sourcing import catalog as _catalog


def _valid(**over):
    base = dict(
        id="11111111-1111-4111-8111-111111111111",
        content_hash="a" * 64,
        text="x" * 30,
        source="src", source_url=None, license="mit", origin_format="jsonl",
        lang="en", token_count=5, char_count=30,
        pipeline_version="0.1.0", collected_at="2026-01-01T00:00:00Z",
        source_file="src", record_type="article",
        domain_label=-1, domain_name="CYBERSEC",
        subdomain_label=-1, subdomain_name="APPLICATION",
        safe_unsafe=None, confidence=None, instruction=None, reviewed_by=None,
    )
    base.update(over)
    return base


def test_valid_record_roundtrips():
    m = CanonicalRecord(**_valid())
    d = m.model_dump()
    assert len(d) == 22
    assert d["domain_label"] == -1 and d["safe_unsafe"] is None


def test_subdomain_enum_has_12():
    assert len(SUBDOMAIN_NAMES) == 12


@pytest.mark.parametrize("field,value", [
    ("text", "tooshort"),
    ("content_hash", "nothex"),
    ("domain_name", "BOGUS"),
    ("subdomain_name", "BOGUS"),
    ("source", "  "),
    ("safe_unsafe", "MAYBE"),
    ("confidence", 2.0),
])
def test_invalid_values_rejected(field, value):
    with pytest.raises(ValidationError):
        CanonicalRecord(**_valid(**{field: value}))


def test_extra_field_forbidden():
    with pytest.raises(ValidationError):
        CanonicalRecord(**_valid(surprise="x"))


def test_unknown_record_type_coerced_to_other():
    m = CanonicalRecord(**_valid(record_type="weird"))
    assert m.record_type == "other"


def test_resolve_domain_cybersec_and_merged_tracks():
    assert resolve_domain("Application Security") == ("CYBERSEC", "APPLICATION")
    # Retired tracks fold onto their merge targets.
    assert resolve_domain("Quantum") == ("CYBERSEC", "CRYPTOGRAPHY")
    assert resolve_domain("Malware Analysis") == ("CYBERSEC", "THREAT_INTELLIGENCE")
    # The old combined domain split into two.
    assert resolve_domain("Penetration Testing") == ("CYBERSEC", "PENTEST")
    assert resolve_domain("Vulnerability Management") == ("CYBERSEC", "VULN_MANAGEMENT")
    # alias / case-insensitive folder name
    assert resolve_domain("appsec")[1] == "APPLICATION"


def test_normalize_domain_rejects_unknown():
    with pytest.raises(ValueError):
        normalize_domain("Underwater Basket Weaving")


def test_default_catalog_matches_legacy_order(tmp_path):
    """On a fresh catalog (no keywords.yaml on disk), the taxonomy derived from
    sourcing.catalog must reproduce today's exact 12-domain order, enum codes,
    and top-level domain_name -- the downstream snorkel LabelModel contract
    depends on this order/naming never silently reshuffling."""
    cat = _catalog.load(str(tmp_path / "missing.yaml"))
    names = tuple(_catalog.subdomains(cat))
    codes = tuple(_catalog.code_for(n, cat) for n in names)

    assert names == CANONICAL_DOMAINS == (
        "Application Security",
        "Cloud Security",
        "Cryptography",
        "Data Security and Privacy",
        "Governance, Risk and Compliance",
        "Identity Access and Management",
        "Incident Response and Forensics",
        "Network Security",
        "Penetration Testing",
        "Security Operations",
        "Threat Intelligence",
        "Vulnerability Management",
    )
    assert codes == SUBDOMAIN_NAMES == (
        "APPLICATION", "CLOUD", "CRYPTOGRAPHY", "DATA_PRIVACY", "GRC", "IAM",
        "INCIDENT_RESPONSE", "NETWORK", "PENTEST", "SECOPS",
        "THREAT_INTELLIGENCE", "VULN_MANAGEMENT",
    )
    assert DOMAIN_NAMES == frozenset({"CYBERSEC"})
