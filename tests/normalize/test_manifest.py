"""Tests for the provenance manifest."""

from __future__ import annotations

import json

from cybersec_slm.normalize import manifest


def _rows(tmp_path):
    ds = tmp_path / "dataset.jsonl"
    rows = [
        {"domain_name": "CYBERSEC", "subdomain_name": "APPLICATION", "source": "a",
         "license": "mit", "origin_format": "jsonl", "record_type": "article",
         "lang": "en", "content_hash": "a" * 64, "token_count": 10, "char_count": 50},
        {"domain_name": "CYBERSEC", "subdomain_name": "NETWORK", "source": "b",
         "license": "mit", "origin_format": "csv", "record_type": "log",
         "lang": "en", "content_hash": "b" * 64, "token_count": 5, "char_count": 25},
        {"domain_name": "CYBERSEC", "subdomain_name": "CRYPTOGRAPHY", "source": "a",
         "license": "gov", "origin_format": "pdf", "record_type": "doc",
         "lang": "en", "content_hash": "c" * 64, "token_count": 20, "char_count": 100},
    ]
    with open(ds, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    return str(ds)


def test_build_manifest_aggregates(tmp_path):
    m = manifest.build_manifest(_rows(tmp_path))
    assert m["record_count"] == 3
    assert m["unique_content_hashes"] == 3
    assert m["domains"] == {"CYBERSEC": 3}
    assert m["sources"]["a"] == 2
    assert set(m["licenses"]) == {"mit", "gov"}
    assert m["token_total"] == 35 and m["char_total"] == 175
    assert m["dataset_sha256"] and len(m["dataset_sha256"]) == 64
    assert m["pipeline_version"]


def test_write_manifest_creates_file(tmp_path):
    ds = _rows(tmp_path)
    out = str(tmp_path / "manifest.json")
    manifest.write_manifest(ds, out=out)
    with open(out, encoding="utf-8") as f:
        doc = json.load(f)
    assert doc["record_count"] == 3
