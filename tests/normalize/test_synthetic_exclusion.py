"""Synthetic-flagged records are diverted from the final dataset, not written."""

from __future__ import annotations

import json
import os

import pandas as pd

from cybersec_slm.ingestion import sources
from cybersec_slm.normalize import pipeline
from cybersec_slm.normalize.synthetic import SyntheticFilter


def _write(path, recs):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")


def _catalog(tmp_path):
    rows = [
        {"Name": "syn", "Dataset Link": "https://huggingface.co/datasets/acme/synthset",
         "Is Synthetic?": "Yes"},
        {"Name": "real", "Dataset Link": "https://huggingface.co/datasets/acme/realset",
         "Is Synthetic?": ""},
    ]
    df = pd.DataFrame([{c: r.get(c, "") for c in sources.CATALOG_COLUMNS} for r in rows])
    p = tmp_path / "cat.csv"
    df.to_csv(p, index=False, encoding="utf-8")
    return str(p)


def test_synthetic_records_excluded(tmp_path, monkeypatch):
    norm = tmp_path / "normalized"
    monkeypatch.setattr(pipeline, "DATASET", str(norm / "dataset.jsonl"))
    monkeypatch.setattr(pipeline, "REJECTED", str(norm / "rejected.jsonl"))
    monkeypatch.setattr(pipeline, "DUPLICATES", str(norm / "duplicates.jsonl"))
    monkeypatch.setattr(pipeline, "DEDUP_SCORES", str(norm / "scores.jsonl"))
    monkeypatch.setattr(pipeline, "EXCLUDED_SYNTHETIC", str(norm / "excluded_synthetic.jsonl"))
    monkeypatch.setattr(pipeline, "REPORT", str(tmp_path / "report.json"))
    # point the filter at the temp catalog instead of sources/Sources.csv
    cat = _catalog(tmp_path)
    monkeypatch.setattr(pipeline, "SyntheticFilter", lambda: SyntheticFilter(cat))

    real_txt = ("SQL injection concatenates untrusted input into a database query "
                "unsafely, letting an attacker read or modify arbitrary rows.")
    syn_txt = ("Synthetic fabricated record describing a made-up cloud "
               "misconfiguration used only to exercise the exclusion path.")
    cdata = tmp_path / "clean"
    _write(str(cdata / "Internal Audit" / "acme" / "a.jsonl"), [
        {"source": "acme", "license": "mit", "text": real_txt,
         "url": "https://huggingface.co/datasets/acme/realset/resolve/main/f.jsonl"},
        {"source": "acme", "license": "mit", "text": syn_txt,
         "url": "https://huggingface.co/datasets/acme/synthset/resolve/main/f.jsonl"},
    ])

    rep = pipeline.Normalizer(resume=False).run(input_dir=str(cdata))
    c = rep["counts"]
    assert c["in"] == 2
    assert c["synthetic_excluded"] == 1
    assert c["written"] == 1
    assert rep["synthetic_ids"] == 1

    ds = [json.loads(ln) for ln in open(norm / "dataset.jsonl", encoding="utf-8")]
    assert len(ds) == 1 and "SQL injection" in ds[0]["text"]

    exc = (norm / "excluded_synthetic.jsonl").read_text(encoding="utf-8")
    assert "synthetic-source" in exc
    assert "acme/synthset" in exc          # provenance url logged
    assert "made-up cloud" not in exc      # metadata-only: no raw text leak
