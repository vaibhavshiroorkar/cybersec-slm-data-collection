import json
import os

import polars as pl
import pytest

from cybersec_slm.ingestion import common


def _read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(ln) for ln in f if ln.strip()]


def test_polars_enrich_adds_provenance_and_text(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text("content,other\nhello world,x\nfoo,y\n", encoding="utf-8")
    out = tmp_path / "out.jsonl"
    meta = {"source": "S", "url": "http://u", "license": "MIT"}
    size = common._polars_to_jsonl(str(src), str(out), common.CAP_BYTES, meta)
    assert size > 0
    recs = _read_jsonl(out)
    assert len(recs) == 2
    assert recs[0]["source"] == "S"
    assert recs[0]["url"] == "http://u"
    assert recs[0]["license"] == "MIT"
    assert recs[0]["text"] == "hello world"       # derived from `content`
    assert recs[0]["other"] == "x"


def test_polars_matches_pandas_provenance(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text("body,n\nalpha,1\nbeta,2\n", encoding="utf-8")
    meta = {"source": "S", "url": "http://u", "license": "MIT"}
    pol = tmp_path / "pol.jsonl"
    common._polars_to_jsonl(str(src), str(pol), common.CAP_BYTES, meta)
    pan = tmp_path / "pan.jsonl"
    df = common.read_any(str(src))
    df = common.enrich_df(df, source="S", url="http://u", lic="MIT")
    common.write_jsonl(df, str(pan))
    keys = ("source", "url", "license", "text")
    pol_rows = [{k: r.get(k) for k in keys} for r in _read_jsonl(pol)]
    pan_rows = [{k: r.get(k) for k in keys} for r in _read_jsonl(pan)]
    assert pol_rows == pan_rows


def test_polars_cap_removes_oversize_output(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text("content\n" + "\n".join(f"row{i}" for i in range(100)) + "\n",
                   encoding="utf-8")
    out = tmp_path / "out.jsonl"
    ret = common._polars_to_jsonl(str(src), str(out), cap=10, meta={"source": "S"})
    assert ret == 11                    # cap + 1
    assert not os.path.exists(out)      # oversize output removed


def test_to_jsonl_falls_back_when_polars_fails(tmp_path, monkeypatch):
    # Force the polars route (threshold 0) then make polars raise; pandas must win.
    monkeypatch.setattr(common, "BIG_FILE_BYTES", 0)

    def boom(*a, **k):
        raise RuntimeError("polars unavailable")

    monkeypatch.setattr(common, "_polars_to_jsonl", boom)
    src = tmp_path / "in.csv"
    src.write_text("content,n\nhi,1\n", encoding="utf-8")
    out = tmp_path / "out.jsonl"
    size = common.to_jsonl(str(src), str(out),
                           meta={"source": "S", "url": "u", "license": "MIT"})
    assert size > 0
    recs = _read_jsonl(out)
    assert recs[0]["text"] == "hi"
    assert recs[0]["source"] == "S"
