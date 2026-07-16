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
        domain_label=-1, domain_name="BANKING_COMPLIANCE",
        subdomain_label=-1, subdomain_name="AML_KYC",
        safe_unsafe=None, confidence=None, instruction=None, reviewed_by=None,
    )
    base.update(over)
    return base


def test_valid_record_roundtrips():
    m = CanonicalRecord(**_valid())
    d = m.model_dump()
    assert len(d) == 22
    assert d["domain_label"] == -1 and d["safe_unsafe"] is None


def test_subdomain_enum_matches_taxonomy():
    assert len(SUBDOMAIN_NAMES) == 4
    assert len(SUBDOMAIN_NAMES) == len(CANONICAL_DOMAINS)


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


def test_resolve_domain_and_aliases():
    D = "BANKING_COMPLIANCE"
    assert resolve_domain("AML-KYC") == (D, "AML_KYC")
    assert resolve_domain("Compliance and Risk Management") == (D, "COMPLIANCE_RISK")
    assert resolve_domain("Internal Audit") == (D, "INTERNAL_AUDIT")
    assert resolve_domain("Corporate Governance") == (D, "CORP_GOVERNANCE")
    # Punctuation / spelling variants fold onto the canonical sub-domain.
    # The slash spelling is what people write; it must still resolve, even
    # though the canonical name avoids it (directory-name safety).
    assert resolve_domain("AML/KYC")[1] == "AML_KYC"
    assert resolve_domain("aml kyc")[1] == "AML_KYC"
    assert resolve_domain("Know Your Customer")[1] == "AML_KYC"
    # The team's own name for the governance track.
    assert resolve_domain("Board Secretariat")[1] == "CORP_GOVERNANCE"
    # Case-insensitive folder name.
    assert resolve_domain("internal audit")[1] == "INTERNAL_AUDIT"


def test_resolve_domain_uses_catalog_label_not_a_literal():
    """The top-level label must come from the live catalog's domain_name.

    resolve_domain used to return a hard-coded "CYBERSEC" while DOMAIN_NAMES was
    read from the catalog, so re-pointing the taxonomy emitted a domain_name the
    schema's own validator then rejected. Guard that they agree."""
    domain_name, _ = resolve_domain("Internal Audit")
    assert domain_name in DOMAIN_NAMES
    CanonicalRecord(**_valid(domain_name=domain_name))


def test_normalize_domain_rejects_unknown():
    with pytest.raises(ValueError):
        normalize_domain("Underwater Basket Weaving")


def test_default_catalog_matches_taxonomy(tmp_path):
    """On a fresh catalog (no keywords.yaml on disk), the taxonomy derived from
    sourcing.catalog must reproduce the exact sub-domain order, enum codes, and
    top-level domain_name -- the downstream snorkel LabelModel contract depends
    on this order/naming never silently reshuffling."""
    cat = _catalog.load(str(tmp_path / "missing.yaml"))
    names = tuple(_catalog.subdomains(cat))
    codes = tuple(_catalog.code_for(n, cat) for n in names)

    # Alphabetical by sub-domain name -- this is the LabelModel index order.
    assert names == CANONICAL_DOMAINS == (
        "AML-KYC",
        "Compliance and Risk Management",
        "Corporate Governance",
        "Internal Audit",
    )
    assert codes == SUBDOMAIN_NAMES == (
        "AML_KYC", "COMPLIANCE_RISK", "CORP_GOVERNANCE", "INTERNAL_AUDIT",
    )
    assert DOMAIN_NAMES == frozenset({"BANKING_COMPLIANCE"})
