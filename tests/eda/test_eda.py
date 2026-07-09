"""Tests for the EDA metrics, sufficiency gate, and drift."""

from __future__ import annotations

import json
import os

import pytest

from cybersec_slm.eda import compute_metrics, evaluate_gate, pipeline
from cybersec_slm.eda.pipeline import SufficiencyError, compute_drift, run_eda


def _write(path, recs):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")


def _corpus(tmp_path, per_source):
    """Build clean_data with `per_source` = {(subdomain, source): n_records}."""
    cdata = tmp_path / "clean_data"
    for (sub, source), n in per_source.items():
        recs = [{"source": source, "text": f"record {i} about {source} cyber defense topics"}
                for i in range(n)]
        _write(str(cdata / sub / source / "a.jsonl"), recs)
    return str(cdata)


def test_metrics_counts_and_concentration(tmp_path):
    cdata = _corpus(tmp_path, {("Network Security", "a"): 8, ("Network Security", "b"): 2})
    m = compute_metrics(cdata)
    assert m["total"] == 10
    assert m["subdomains"]["Network Security"] == 10
    # source 'a' is 8/10 of the subdomain
    assert m["concentration"]["source"] == "a"
    assert m["concentration"]["worst_share"] == pytest.approx(0.8)


def test_gate_flags_concentration_and_volume(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline.config, "MIN_TOTAL_RECORDS", 100)
    monkeypatch.setattr(pipeline.config, "MAX_SOURCE_SHARE", 0.6)
    cdata = _corpus(tmp_path, {("Network Security", "a"): 8, ("Network Security", "b"): 2})
    m = compute_metrics(cdata)
    checks = {v["check"]: v["severity"] for v in evaluate_gate(m)}
    assert checks["volume"] == "blocker"          # 10 < 100
    assert checks["concentration"] == "blocker"   # 0.8 > 0.6


def test_drift_vs_previous():
    cur = {"Network Security": 0.5, "Cloud Security": 0.5}
    prev = {"metrics": {"subdomain_distribution": {"Network Security": 0.9, "Cloud Security": 0.1}}}
    d = compute_drift(cur, prev)
    assert d["available"] and d["max_delta"] == pytest.approx(0.4)


def test_run_eda_raises_on_blocker(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "EDA_DIR", str(tmp_path / "eda"))
    monkeypatch.setattr(pipeline.config, "MIN_TOTAL_RECORDS", 100)
    cdata = _corpus(tmp_path, {("Network Security", "a"): 5})
    with pytest.raises(SufficiencyError):
        run_eda(cdata, enforce=True)
    # a run report is still persisted for the audit trail
    assert os.path.exists(str(tmp_path / "eda" / "latest.json"))


def test_run_eda_passes_and_persists(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "EDA_DIR", str(tmp_path / "eda"))
    monkeypatch.setattr(pipeline.config, "MIN_TOTAL_RECORDS", 1)
    monkeypatch.setattr(pipeline.config, "MAX_SOURCE_SHARE", 0.95)
    # two balanced sources per subdomain -> 50% concentration, under the ceiling
    cdata = _corpus(tmp_path, {("Network Security", "a"): 3, ("Network Security", "b"): 3,
                               ("Cloud Security", "c"): 3, ("Cloud Security", "d"): 3})
    report = run_eda(cdata, enforce=True)
    assert report["passed"] is True
    assert report["metrics"]["total"] == 12


# ── v2: topic balance tests ─────────────────────────────────────────────────

def test_metrics_includes_topic_cv(tmp_path):
    """The compute_metrics output should include topic_cv."""
    cdata = _corpus(tmp_path, {("Network Security", "a"): 10,
                               ("Cloud Security", "b"): 10})
    m = compute_metrics(cdata)
    assert "topic_cv" in m
    # Two equal subdomains -> CV should be 0 or very small
    assert m["topic_cv"] == pytest.approx(0.0, abs=0.01)


def test_topic_cv_high_for_skewed_corpus(tmp_path):
    """Skewed corpus should have a high topic CV."""
    cdata = _corpus(tmp_path, {("Network Security", "a"): 100,
                               ("Cloud Security", "b"): 1})
    m = compute_metrics(cdata)
    assert m["topic_cv"] > 1.0  # heavily skewed


def test_metrics_includes_per_subdomain_quality(tmp_path):
    cdata = _corpus(tmp_path, {("Network Security", "a"): 5,
                               ("Cloud Security", "b"): 5})
    m = compute_metrics(cdata)
    assert "per_subdomain_quality" in m
    assert "Network Security" in m["per_subdomain_quality"]
    q = m["per_subdomain_quality"]["Network Security"]
    assert "avg_tokens" in q
    assert "records" in q
    assert q["records"] == 5


def test_gate_warns_on_high_topic_cv(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline.config, "MAX_TOPIC_CV", 0.5)
    cdata = _corpus(tmp_path, {("Network Security", "a"): 100,
                               ("Cloud Security", "b"): 1})
    m = compute_metrics(cdata)
    checks = {v["check"]: v for v in evaluate_gate(m)}
    assert "topic_balance" in checks
    assert checks["topic_balance"]["severity"] == "warning"


def test_feedback_section_in_report(tmp_path, monkeypatch):
    """run_eda should include a 'feedback' section in the report."""
    monkeypatch.setattr(pipeline, "EDA_DIR", str(tmp_path / "eda"))
    monkeypatch.setattr(pipeline.config, "MIN_TOTAL_RECORDS", 1)
    monkeypatch.setattr(pipeline.config, "MAX_SOURCE_SHARE", 0.95)
    monkeypatch.setattr(pipeline.config, "AUTO_REBALANCE", False)
    cdata = _corpus(tmp_path, {("Network Security", "a"): 5,
                               ("Cloud Security", "b"): 5})
    report = run_eda(cdata, enforce=False)
    assert "feedback" in report
    fb = report["feedback"]
    assert "under_represented" in fb
    assert "over_represented" in fb
    assert "quality_concerns" in fb
    assert "recommendations" in fb


def test_feedback_identifies_over_represented(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "EDA_DIR", str(tmp_path / "eda"))
    monkeypatch.setattr(pipeline.config, "MIN_TOTAL_RECORDS", 1)
    monkeypatch.setattr(pipeline.config, "MAX_SOURCE_SHARE", 0.99)
    monkeypatch.setattr(pipeline.config, "AUTO_REBALANCE", False)
    # Network Security has 10000 records, 4 other subdomains have 10 each
    # avg = (10000+10+10+10+10)/5 = 2008, 4*2008 = 8032, 10000 > 8032 -> over
    cdata = _corpus(tmp_path, {("Network Security", "a"): 10000,
                               ("Cloud Security", "b"): 10,
                               ("Vulnerability Management", "c"): 10,
                               ("Cryptography", "d"): 10,
                               ("Data Security and Privacy", "e"): 10})
    report = run_eda(cdata, enforce=False)
    over = report["feedback"]["over_represented"]
    assert len(over) > 0
    over_subs = {e["subdomain"] for e in over}
    assert "Network Security" in over_subs

