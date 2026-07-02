"""Core JSONL I/O: the orjson fast path must keep stdlib-json semantics exactly."""

import json
import math
import os

from cybersec_slm.core import PARSE_ERROR, JsonlWriter, iter_jsonl, json_dumps, json_loads


def test_json_dumps_roundtrip_and_unicode():
    rec = {"text": "чистый текст — привет", "n": 3, "nested": {"a": [1, 2.5, None, True]}}
    line = json_dumps(rec)
    assert json.loads(line) == rec
    assert "чистый" in line                    # non-ASCII kept raw, not \u-escaped


def test_json_dumps_big_int_falls_back_to_stdlib():
    huge = 2 ** 100                             # >64-bit: orjson refuses, stdlib handles
    assert json.loads(json_dumps({"n": huge}))["n"] == huge


def test_json_loads_accepts_nan_via_fallback():
    # stdlib json accepts NaN/Infinity literals; orjson rejects them. The helper
    # must keep the permissive stdlib behaviour so no previously-parseable line
    # silently becomes a parse error.
    obj = json_loads('{"v": NaN}')
    assert math.isnan(obj["v"])


def test_iter_jsonl_mixed_lines(tmp_path):
    p = tmp_path / "x.jsonl"
    p.write_text('{"a": 1}\n'
                 "\n"                            # blank -> skipped
                 "not json at all\n"             # malformed -> PARSE_ERROR
                 "[1, 2]\n"                      # valid JSON, not a dict -> PARSE_ERROR
                 '{"v": NaN}\n'                  # stdlib-only literal -> parsed
                 '{"b": "ok"}\n', encoding="utf-8")
    recs = list(iter_jsonl(str(p)))
    assert recs[0] == {"a": 1}
    assert recs[1].get(PARSE_ERROR) and recs[1]["_line"] == 3
    assert recs[2].get(PARSE_ERROR) and recs[2]["_line"] == 4
    assert math.isnan(recs[3]["v"])
    assert recs[4] == {"b": "ok"}


def test_jsonl_writer_roundtrip(tmp_path):
    path = str(tmp_path / "out" / "w.jsonl")
    rows = [{"text": "первый", "i": 0}, {"text": "second", "i": 1}]
    with JsonlWriter(path) as w:
        for r in rows:
            w.write(r)
    assert w.count == 2
    assert os.path.exists(path)
    assert list(iter_jsonl(path)) == rows
