"""Tests for source mappers + record enrichment."""

from __future__ import annotations

from cybersec_slm.normalize import enrich, mappers
from cybersec_slm.normalize.schema import CanonicalRecord


def test_prose_mapper_extracts_text_and_provenance():
    rec = {"source": "Feed", "url": "https://x/1", "license": "mit",
           "text": "A genuine sentence of prose about network defense and monitoring."}
    out = mappers.get_mapper("feed", rec).map(rec, domain="Network Security", source="feed")
    assert out["source"] == "feed"          # the pipeline's source, not the record's
    assert out["source_url"] == "https://x/1"
    assert out["raw_domain"] == "Network Security"
    assert out["source_file"] == "feed"


def test_a_datasets_own_source_column_cannot_hijack_provenance():
    """Provenance is which source folder a record came from, and only the pipeline
    knows that. Plenty of datasets ship a column called ``source`` meaning
    something else entirely (a citation, a URL, a sentence of prose). Ingestion's
    enrich_df skips injecting provenance when such a column already exists, so the
    dataset's own value reached here and was filed as the corpus source: 61% of the
    records in the live corpus were filed under 188 prose "sources", which made the
    Final row claim more sources than data/clean has folders.
    """
    rec = {"source": "215 cloud security controls across Azure, AWS and GCP, "
                     "based on CIS Benchmarks. - secvalley/cloud-security-checklist",
           "text": "Rotate service account keys every ninety days without fail."}

    out = mappers.get_mapper("secvalley", rec).map(
        rec, domain="Internal Audit", source="secvalley")

    assert out["source"] == "secvalley"
    assert out["source_file"] == "secvalley"


def test_build_record_files_a_hijacked_record_under_its_real_source():
    """The end of the chain: what the manifest and the corpus funnel count."""
    rec = {"source": "This synthetic dataset for LLM training captures realistic "
                     "employee-assistant interactions about HR and compliance.",
           "text": "Customer due diligence requires verifying the beneficial owner."}
    mapped = mappers.get_mapper("hr-corpus", rec).map(
        rec, domain="AML-KYC", source="hr-corpus")

    record = enrich.build_record(mapped)

    assert record["source"] == "hr-corpus"


def test_structured_mapper_serializes_columns():
    rec = {"protocol": "tcp", "flag": "SYN", "label": "attack"}
    out = mappers.get_mapper("flows", rec).map(rec, domain="Network Security", source="flows")
    assert out is not None
    assert "protocol: tcp" in out["text"]


def test_dispatch_prefers_prose_when_text_present():
    assert isinstance(mappers.get_mapper("x", {"text": "hi there"}), mappers.ProseMapper)
    assert isinstance(mappers.get_mapper("y", {"a": 1}), mappers.StructuredMapper)


def test_origin_format_inferred_from_file_hint():
    rec = {"text": "something readable here", "_file": "rules.yar"}
    out = mappers.ProseMapper().map(rec, domain="AML-KYC", source="yara")
    assert out["origin_format"] == "yara"


def test_build_record_full_contract_validates():
    mapped = mappers.ProseMapper().map(
        {"text": "Customer due diligence requires verifying the beneficial owner of an account."},
        domain="AML-KYC", source="cdd")
    record = enrich.build_record(mapped)
    model = CanonicalRecord(**record)               # must validate
    assert model.domain_name == "BANKING_COMPLIANCE"
    assert model.subdomain_name == "AML_KYC"
    assert model.domain_label == -1 and model.subdomain_label == -1
    assert model.content_hash == enrich.content_hash(model.text)
    assert model.char_count == len(model.text)


def test_classify_record_type():
    assert enrich.classify_record_type("nvd-cve", "NVD") == "cve"
    assert enrich.classify_record_type("mitre-attack-web") == "advisory"
    assert enrich.classify_record_type("aws-cloudtrail") == "log"
    assert enrich.classify_record_type("nist-sp800-61") == "doc"
    assert enrich.classify_record_type("random-blog") == "article"
