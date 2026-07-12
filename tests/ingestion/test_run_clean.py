"""run_clean cleans the whole raw tree, cross-source dedups, and drops raw."""

from __future__ import annotations

import json
import os

from cybersec_slm.cleaning import pipeline
from cybersec_slm.ingestion import parallel


def _write_jsonl(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def _read_all(root):
    text = ""
    for r, _d, fs in os.walk(root):
        for fn in fs:
            if fn.endswith(".jsonl"):
                with open(os.path.join(r, fn), encoding="utf-8") as f:
                    text += f.read()
    return text


class _StubRedactor:
    def redact(self, text):
        return text, 0


class _StubLang:
    def detect(self, text):
        return "en"

    def lang_allowed(self, lang):
        return True


class _StubTranslator:
    backend = "stub"

    def translate(self, text, src=None):
        return text, True


def _wire(monkeypatch, tmp_path):
    raw = tmp_path / "raw"
    monkeypatch.setattr(parallel.core, "RAW_DATA", str(raw))
    monkeypatch.setattr(pipeline, "OUT_CLEAN_DATA", str(tmp_path / "clean"))
    monkeypatch.setattr(pipeline, "OUT_FLAGGED", str(tmp_path / "flagged"))
    monkeypatch.setattr(pipeline, "OUT_DROPPED", str(tmp_path / "dropped"))
    monkeypatch.setattr(pipeline, "REPORTS", str(tmp_path / "reports"))
    monkeypatch.setattr(pipeline, "DEDUP_CKPT", str(tmp_path / "ckpt.json"))
    monkeypatch.setattr(pipeline, "DEDUP_DONE", str(tmp_path / "done.json"))
    monkeypatch.setattr(pipeline, "Redactor", _StubRedactor)
    monkeypatch.setattr(pipeline, "LangFilter", _StubLang)
    monkeypatch.setattr(pipeline, "Translator", _StubTranslator)
    pipeline.reset_cleaner_cache()

    dup = ("This is a shared malware analysis record with enough descriptive prose "
           "to pass the anomaly gate and appear in two different sources at once.")
    distinct = ("A distinct network-security record long enough to survive the "
                "cleaning pipeline and remain in the corpus after deduplication runs.")
    _write_jsonl(str(raw / "Test" / "s1" / "a.jsonl"),
                 [{"text": dup}, {"text": distinct}])
    _write_jsonl(str(raw / "Test" / "s2" / "b.jsonl"),
                 [{"text": dup}])           # cross-source duplicate of s1's record
    return raw, dup, distinct


def test_run_clean_cleans_dedups_and_deletes_raw(tmp_path, monkeypatch):
    raw, dup, distinct = _wire(monkeypatch, tmp_path)
    result = parallel.run_clean(keep_raw=False)

    clean_dir = tmp_path / "clean"
    text = _read_all(str(clean_dir))
    # both distinct records survive once; the cross-source dup is removed once
    assert text.count(dup) == 1
    assert text.count(distinct) == 1
    assert result["dedup"]["exact_dups"] >= 1
    # clean report written
    assert (tmp_path / "reports" / "clean_report.csv").exists()
    # raw deleted by default
    assert not raw.exists()
    pipeline.reset_cleaner_cache()


def test_run_clean_keep_raw_retains_raw(tmp_path, monkeypatch):
    raw, _dup, _distinct = _wire(monkeypatch, tmp_path)
    parallel.run_clean(keep_raw=True)
    assert raw.exists()
    pipeline.reset_cleaner_cache()
