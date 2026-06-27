"""Tests for source mappers + record enrichment."""

from __future__ import annotations

from cybersec_slm.normalize import enrich, mappers
from cybersec_slm.normalize.schema import CanonicalRecord


def test_prose_mapper_extracts_text_and_provenance():
    rec = {"source": "Feed", "url": "https://x/1", "license": "mit",
           "text": "A genuine sentence of prose about network defense and monitoring."}
    out = mappers.get_mapper("feed", rec).map(rec, domain="Network Security", source="feed")
    assert out["source"] == "Feed"
    assert out["source_url"] == "https://x/1"
    assert out["raw_domain"] == "Network Security"
    assert out["source_file"] == "feed"


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
    out = mappers.ProseMapper().map(rec, domain="Malware Analysis", source="yara")
    assert out["origin_format"] == "yara"


def test_build_record_full_contract_validates():
    mapped = mappers.ProseMapper().map(
        {"text": "Phishing emails impersonate trusted brands to steal credentials from victims."},
        domain="Threat Intelligence", source="phish")
    record = enrich.build_record(mapped)
    model = CanonicalRecord(**record)               # must validate
    assert model.domain_name == "CYBERSEC"
    assert model.subdomain_name == "THREAT_INTELLIGENCE"
    assert model.domain_label == -1 and model.subdomain_label == -1
    assert model.content_hash == enrich.content_hash(model.text)
    assert model.char_count == len(model.text)


def test_classify_record_type():
    assert enrich.classify_record_type("nvd-cve", "NVD") == "cve"
    assert enrich.classify_record_type("mitre-attack-web") == "advisory"
    assert enrich.classify_record_type("aws-cloudtrail") == "log"
    assert enrich.classify_record_type("nist-sp800-61") == "doc"
    assert enrich.classify_record_type("random-blog") == "article"
