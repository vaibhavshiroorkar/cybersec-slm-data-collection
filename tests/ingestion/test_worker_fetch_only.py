"""process_source(clean=False) fetches + gates but never cleans (ingest stage)."""

from __future__ import annotations

import os

from cybersec_slm.cleaning import pipeline as cleaning_pipeline
from cybersec_slm.ingestion import worker


def _wire(monkeypatch, tmp_path):
    """Stub the fetch + gates so the source passes into (or past) the clean step."""
    folder = tmp_path / "raw" / "D" / "src"
    folder.mkdir(parents=True)
    (folder / "data.jsonl").write_text('{"text": "hello world"}\n', encoding="utf-8")

    monkeypatch.setattr(worker, "is_license_ok", lambda d: (True, None))
    monkeypatch.setattr(worker, "_fetch_one", lambda d, log: str(folder))
    monkeypatch.setattr(worker, "_get_synthetic_ids", lambda: frozenset())
    monkeypatch.setattr(worker.light_eda, "assess_source",
                        lambda folder, descriptor, synthetic_ids=None,
                        scan_hazards=True: (True, {"flags": {"synthetic": False}}))
    return str(folder)


def _sentinel_clean(*a, **k):
    raise AssertionError("clean_one_source must not be called when clean=False")


def test_fetch_only_skips_clean_and_keeps_raw(tmp_path, monkeypatch):
    folder = _wire(monkeypatch, tmp_path)
    monkeypatch.setattr(cleaning_pipeline, "clean_one_source", _sentinel_clean)

    descriptor = {"kind": "url", "url": "http://a", "domain": "D",
                  "license": "MIT", "description": ""}
    result = worker.process_source(descriptor, clean=False)

    assert result["status"] == "ok"
    assert result["clean_rows"] == []
    assert result["folder"] == folder
    assert os.path.isdir(folder)          # raw is left in place for the clean stage


def test_default_still_cleans(tmp_path, monkeypatch):
    _wire(monkeypatch, tmp_path)
    called = {"n": 0}

    def _clean(folder, *, limit=None):
        called["n"] += 1
        return [{"file": folder, "in": 1, "out": 1}]

    monkeypatch.setattr(cleaning_pipeline, "clean_one_source", _clean)

    descriptor = {"kind": "url", "url": "http://a", "domain": "D",
                  "license": "MIT", "description": ""}
    result = worker.process_source(descriptor)     # clean defaults to True

    assert called["n"] == 1
    assert result["clean_rows"] == [{"file": result["folder"], "in": 1, "out": 1}]
