"""End-to-end tests for the normalize orchestrator."""

from __future__ import annotations

import json
import os

from cybersec_slm.core import DEFAULT_PROFILE as PROFILE
from cybersec_slm.normalize import pipeline
from cybersec_slm.normalize.schema import CanonicalRecord


def _write(path, recs):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")


def _redirect(tmp_path, monkeypatch):
    norm = tmp_path / "normalized"
    monkeypatch.setattr(pipeline, "DATASET", str(norm / "dataset.jsonl"))
    monkeypatch.setattr(pipeline, "REJECTED", str(norm / "rejected.jsonl"))
    monkeypatch.setattr(pipeline, "DUPLICATES", str(norm / "duplicates.jsonl"))
    monkeypatch.setattr(pipeline, "DEDUP_SCORES", str(norm / "scores.jsonl"))
    monkeypatch.setattr(pipeline, "REPORT", str(tmp_path / "logs" / PROFILE / "report.json"))
    return norm


def _corpus(tmp_path):
    cdata = tmp_path / "clean_data"
    xss = "Cross-site scripting injects script into a trusted page viewed by users."
    sql = "SQL injection concatenates untrusted input into a database query unsafely."
    _write(str(cdata / "Internal Audit" / "websec" / "a.jsonl"), [
        {"source": "S", "url": "https://x/1", "license": "mit", "text": xss},
        {"source": "S", "url": "https://x/1", "license": "mit", "text": xss},   # exact dup
        {"source": "S", "url": "https://x/2", "license": "mit", "text": "tiny"},  # reject
        {"source": "S", "url": "https://x/3", "license": "mit", "text": sql},
    ])
    return cdata


def test_normalize_end_to_end(tmp_path, monkeypatch):
    norm = _redirect(tmp_path, monkeypatch)
    cdata = _corpus(tmp_path)

    rep = pipeline.Normalizer(resume=False).run(input_dir=str(cdata))
    c = rep["counts"]
    assert c["in"] == 4
    assert c["written"] == 2
    assert c["exact_dups"] == 1
    assert c["rejected"] == 1
    assert rep["reject_categories"]["DIRTY_DATA"] == 1

    rows = [json.loads(line) for line in open(norm / "dataset.jsonl", encoding="utf-8")]
    assert len(rows) == 2
    for r in rows:
        CanonicalRecord(**r)                      # every output validates

    # rejection log is metadata-only — the raw short text must not leak
    rej = (norm / "rejected.jsonl").read_text(encoding="utf-8")
    assert "tiny" not in rej and "DIRTY_DATA" in rej

    # a similarity score is logged for every record that reaches dedup (2 + 1 dup)
    scores = [json.loads(line) for line in open(norm / "scores.jsonl", encoding="utf-8")]
    assert len(scores) == 3
    assert any(s["reason"] == "exact" and s["score"] == 1.0 for s in scores)


def test_resume_does_not_bloat_dup_sinks_or_recount(tmp_path, monkeypatch):
    """A second (resume) pass over the SAME clean tree must not re-append every
    already-written record to duplicates.jsonl / scores.jsonl or re-count them as
    exact_dups. dataset.jsonl must be byte-for-byte unchanged."""
    norm = _redirect(tmp_path, monkeypatch)
    cdata = _corpus(tmp_path)

    rep1 = pipeline.Normalizer(resume=False).run(input_dir=str(cdata))
    assert rep1["counts"]["written"] == 2
    assert rep1["counts"]["exact_dups"] == 1

    dataset_before = (norm / "dataset.jsonl").read_text(encoding="utf-8")
    dup_before = sum(1 for _ in open(norm / "duplicates.jsonl", encoding="utf-8"))
    scores_before = sum(1 for _ in open(norm / "scores.jsonl", encoding="utf-8"))

    rep2 = pipeline.Normalizer(resume=True).run(input_dir=str(cdata))

    # Nothing new written; the corpus is unchanged.
    assert (norm / "dataset.jsonl").read_text(encoding="utf-8") == dataset_before
    assert rep2["counts"]["written"] == 0
    # Already-written records are NOT re-counted or re-logged on resume.
    assert rep2["counts"]["exact_dups"] == 0
    assert sum(1 for _ in open(norm / "duplicates.jsonl", encoding="utf-8")) == dup_before
    assert sum(1 for _ in open(norm / "scores.jsonl", encoding="utf-8")) == scores_before


def test_debug_flag_includes_raw_record(tmp_path, monkeypatch):
    norm = _redirect(tmp_path, monkeypatch)
    monkeypatch.setattr(pipeline, "DEBUG_REJECTS", True)
    cdata = tmp_path / "clean_data"
    _write(str(cdata / "Internal Audit" / "s" / "a.jsonl"),
           [{"source": "S", "text": "tiny"}])     # rejected: too short

    pipeline.Normalizer(resume=False).run(input_dir=str(cdata))
    rej = (norm / "rejected.jsonl").read_text(encoding="utf-8")
    assert "tiny" in rej                            # raw record present under debug
