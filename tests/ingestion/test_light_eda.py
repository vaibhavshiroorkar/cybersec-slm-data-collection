"""Tests for the per-source light EDA quality gate."""

from __future__ import annotations

import json
import os

from cybersec_slm.ingestion import light_eda


def _write_jsonl(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def _descriptor(**overrides):
    base = {"kind": "hf", "ref": "org/test", "domain": "Network Security",
            "license": "MIT", "description": "test", "url": "https://hf.co/datasets/org/test"}
    base.update(overrides)
    return base


def _source_folder(tmp_path, records, sub="Network Security", source="test"):
    folder = tmp_path / "raw" / sub / source
    _write_jsonl(str(folder / "data.jsonl"), records)
    return str(folder)


# ── Rejection tests ──────────────────────────────────────────────────────────

def test_reject_empty_folder(tmp_path):
    folder = str(tmp_path / "raw" / "empty")
    os.makedirs(folder)
    passed, report = light_eda.assess_source(folder, _descriptor(), synthetic_ids=frozenset())
    assert not passed
    assert "no JSONL" in report["reject_reason"]


def test_reject_all_parse_errors(tmp_path):
    folder = tmp_path / "raw" / "broken"
    p = folder / "data.jsonl"
    os.makedirs(folder)
    with open(str(p), "w") as f:
        f.write("not json\n" * 5)
    passed, report = light_eda.assess_source(str(folder), _descriptor(),
                                              synthetic_ids=frozenset())
    assert not passed
    assert "0 valid records" in report["reject_reason"]


def test_reject_high_empty_text_rate(tmp_path):
    records = [{"text": ""} for _ in range(9)] + [{"text": "some real content here"}]
    folder = _source_folder(tmp_path, records)
    passed, report = light_eda.assess_source(folder, _descriptor(),
                                              synthetic_ids=frozenset())
    assert not passed
    assert "empty-text rate" in report["reject_reason"]


def test_reject_high_garbage_ratio(tmp_path):
    garbage = "".join(chr(i) for i in range(0x2600, 0x2700)) * 20
    records = [{"text": garbage} for _ in range(10)]
    folder = _source_folder(tmp_path, records)
    passed, report = light_eda.assess_source(folder, _descriptor(),
                                              synthetic_ids=frozenset())
    assert not passed
    assert "garbage ratio" in report["reject_reason"]


# ── Pass tests ───────────────────────────────────────────────────────────────

def test_pass_good_source(tmp_path):
    records = [{"text": f"This is a good record about cybersecurity topic {i} "
                        f"with enough content to pass the quality check."}
               for i in range(10)]
    folder = _source_folder(tmp_path, records)
    passed, report = light_eda.assess_source(folder, _descriptor(),
                                              synthetic_ids=frozenset())
    assert passed
    assert report["reject_reason"] is None
    assert report["record_count"] == 10


# ── Flag tests ───────────────────────────────────────────────────────────────

def test_flag_synthetic_source(tmp_path, monkeypatch):
    records = [{"text": f"Synthetic data record {i} about network defense"}
               for i in range(5)]
    folder = _source_folder(tmp_path, records)
    # The descriptor's URL matches a synthetic identity
    desc = _descriptor(url="https://huggingface.co/datasets/org/test")
    syn_ids = frozenset({"hf:org/test"})
    passed, report = light_eda.assess_source(folder, desc, synthetic_ids=syn_ids)
    assert passed  # synthetic sources pass the gate (they are flagged, not rejected)
    assert report["flags"]["synthetic"] is True


def test_flag_license_risk(tmp_path):
    records = [{"text": f"Record {i} about vulnerability analysis methodology"}
               for i in range(5)]
    folder = _source_folder(tmp_path, records)
    desc = _descriptor(license="GPL-3.0")
    passed, report = light_eda.assess_source(folder, desc, synthetic_ids=frozenset())
    assert passed  # license risk is a flag, not a rejection at this stage
    assert report["flags"]["license_risk"] is not None


def test_flag_security_hazards(tmp_path):
    records = [
        {"text": "Normal cybersecurity text about vulnerabilities"},
        {"text": "Exploit payload: <script>alert('xss')</script> in the wild"},
        {"text": "Normal incident response procedure document"},
    ]
    folder = _source_folder(tmp_path, records)
    passed, report = light_eda.assess_source(folder, _descriptor(),
                                              synthetic_ids=frozenset())
    assert passed
    assert len(report["flags"]["security_hazards"]) > 0


# ── reject_source tests ─────────────────────────────────────────────────────

def test_reject_source_moves_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(light_eda, "DROPPED", str(tmp_path / "dropped"))
    records = [{"text": ""}]
    folder = _source_folder(tmp_path, records)
    report = {"reject_reason": "test", "source": "test"}
    light_eda.reject_source(folder, report)
    # Original folder should be moved
    assert not os.path.exists(folder)
