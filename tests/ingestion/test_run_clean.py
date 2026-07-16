"""run_clean cleans the whole raw tree, cross-source dedups, and drops raw."""

from __future__ import annotations

import json
import os
from concurrent.futures import Future

from cybersec_slm.cleaning import pipeline
from cybersec_slm.ingestion import parallel


class _InlineExecutor:
    """Synchronous stand-in for ProcessPoolExecutor: submit runs now, in-process.

    A REAL pool spawns workers that re-import the package and rebuild their own
    data-root globals, so this module's redirected output dirs would be invisible
    to them and the test would clean straight into the live corpus. (That is not
    hypothetical: it is what put a `Test/` tree under a real data/clean.) Running
    inline keeps the redirection honest and the test fast.
    """

    _processes: dict = {}

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def submit(self, fn, *args, **kwargs):
        fut = Future()
        try:
            fut.set_result(fn(*args, **kwargs))
        except Exception as e:  # noqa: BLE001
            fut.set_exception(e)
        return fut

    def shutdown(self, *a, **k):
        pass


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
    logs = tmp_path / "logs"
    monkeypatch.setattr(parallel.core, "RAW_DATA", str(raw))
    monkeypatch.setattr(parallel.core, "LOGS", str(logs))
    monkeypatch.setattr(parallel, "CLEANED_LEDGER", str(logs / "cleaned_sources.txt"))
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


def test_run_clean_cleans_and_dedups(tmp_path, monkeypatch):
    raw, dup, distinct = _wire(monkeypatch, tmp_path)
    result = parallel.run_clean()

    clean_dir = tmp_path / "clean"
    text = _read_all(str(clean_dir))
    # both distinct records survive once; the cross-source dup is removed once
    assert text.count(dup) == 1
    assert text.count(distinct) == 1
    assert result["dedup"]["exact_dups"] >= 1
    # clean report written
    assert (tmp_path / "reports" / "clean_report.csv").exists()
    pipeline.reset_cleaner_cache()


def test_run_clean_resume_skips_already_cleaned_sources(tmp_path, monkeypatch):
    raw, dup, distinct = _wire(monkeypatch, tmp_path)
    # First run cleans both sources and writes the checkpoint.
    result1 = parallel.run_clean()
    assert result1["files"] == 2
    assert (tmp_path / "logs" / "cleaned_sources.txt").exists()

    # Add a new source and rerun with resume. The already-cleaned sources should be skipped.
    _write_jsonl(str(raw / "Test" / "s3" / "c.jsonl"), [{"text": distinct}])
    result2 = parallel.run_clean(resume=True)

    assert result2["files"] == 1
    cleaned = (tmp_path / "logs" / "cleaned_sources.txt").read_text(encoding="utf-8").splitlines()
    assert "Test/s1" in cleaned
    assert "Test/s2" in cleaned
    assert "Test/s3" in cleaned
    pipeline.reset_cleaner_cache()


def test_sharded_source_is_ledgered_only_when_every_window_is_done(tmp_path,
                                                                   monkeypatch):
    """The ledger must keep meaning "fully cleaned, skip on resume".

    A big file is split across workers, so a source now finishes in several
    pieces. Recording it after the first piece would let a resume skip a source
    whose file was only half cleaned - silently losing records from the corpus.
    """
    _raw, _dup, _distinct = _wire(monkeypatch, tmp_path)
    # One record per window, so s1 (2 records) really is split in two.
    monkeypatch.setattr(pipeline, "SHARD_MIN_BYTES", 1)
    monkeypatch.setattr(pipeline, "SHARD_TARGET_RECORDS", 1)
    monkeypatch.setattr(parallel, "ProcessPoolExecutor", _InlineExecutor)

    result = parallel.run_clean(workers=2)
    cleaned = (tmp_path / "logs" / "cleaned_sources.txt").read_text(
        encoding="utf-8").split()

    # Each source appears exactly ONCE, however many windows it took.
    assert sorted(cleaned) == ["Test/s1", "Test/s2"]
    assert cleaned.count("Test/s1") == 1
    # s1's 2 records became 2 windows -> 3 report rows across the 2 sources.
    assert result["files"] == 3
    pipeline.reset_cleaner_cache()


def test_sharded_clean_keeps_every_record(tmp_path, monkeypatch):
    """Sharding is a scheduling change: the corpus it produces is unchanged."""
    _raw, dup, distinct = _wire(monkeypatch, tmp_path)
    monkeypatch.setattr(pipeline, "SHARD_MIN_BYTES", 1)
    monkeypatch.setattr(pipeline, "SHARD_TARGET_RECORDS", 1)
    monkeypatch.setattr(parallel, "ProcessPoolExecutor", _InlineExecutor)

    parallel.run_clean(workers=2)
    body = _read_all(str(tmp_path / "clean"))
    # s1's two records survive; s2's copy of `dup` is the cross-source duplicate
    # that final_global_dedup removes -- exactly as without sharding.
    assert distinct in body
    assert body.count(dup) == 1
    pipeline.reset_cleaner_cache()


def test_run_clean_retains_raw_by_default(tmp_path, monkeypatch):
    raw, _dup, _distinct = _wire(monkeypatch, tmp_path)
    parallel.run_clean()                 # default keeps raw after ingestion
    assert raw.exists()
    pipeline.reset_cleaner_cache()


def test_run_clean_keep_raw_false_deletes_raw(tmp_path, monkeypatch):
    raw, _dup, _distinct = _wire(monkeypatch, tmp_path)
    parallel.run_clean(keep_raw=False)   # explicit purge
    assert not raw.exists()
    pipeline.reset_cleaner_cache()


def _wire_two_domains(monkeypatch, tmp_path):
    raw = tmp_path / "raw"
    logs = tmp_path / "logs"
    monkeypatch.setattr(parallel.core, "RAW_DATA", str(raw))
    monkeypatch.setattr(parallel.core, "LOGS", str(logs))
    monkeypatch.setattr(parallel, "CLEANED_LEDGER", str(logs / "cleaned_sources.txt"))
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

    rec_a = ("An application-security record with enough descriptive prose to pass "
             "the anomaly gate and land in the cleaned corpus for sub-domain A.")
    rec_b = ("A network-security record, also long enough to survive the cleaning "
             "pipeline and remain in the corpus, belonging to sub-domain B.")
    _write_jsonl(str(raw / "DomA" / "s1" / "a.jsonl"), [{"text": rec_a}])
    _write_jsonl(str(raw / "DomB" / "s2" / "b.jsonl"), [{"text": rec_b}])
    return raw


def test_run_clean_selective_cleans_only_chosen_and_preserves_others(tmp_path, monkeypatch):
    raw = _wire_two_domains(monkeypatch, tmp_path)
    clean_dir = tmp_path / "clean"
    # a pre-existing cleaned artifact for DomB that a selective clean of DomA must keep
    preexisting = clean_dir / "DomB" / "s2" / "kept.jsonl"
    os.makedirs(os.path.dirname(preexisting), exist_ok=True)
    preexisting.write_text('{"kept": true}\n', encoding="utf-8")

    result = parallel.run_clean(domains=["DomA"], keep_raw=True)

    assert result["files"] == 1                      # only DomA cleaned
    assert (clean_dir / "DomA").is_dir()             # DomA cleaned output written
    assert preexisting.exists()                      # DomB cleaned output preserved
    assert (raw / "DomB").is_dir()                   # DomB raw untouched
    pipeline.reset_cleaner_cache()


def test_run_clean_selective_purge_raw_deletes_only_chosen(tmp_path, monkeypatch):
    raw = _wire_two_domains(monkeypatch, tmp_path)
    parallel.run_clean(domains=["DomA"], keep_raw=False)
    assert not (raw / "DomA").exists()               # chosen raw purged
    assert (raw / "DomB").is_dir()                   # other raw preserved
    pipeline.reset_cleaner_cache()


def _wire_two_sources_one_domain(monkeypatch, tmp_path):
    raw = tmp_path / "raw"
    logs = tmp_path / "logs"
    monkeypatch.setattr(parallel.core, "RAW_DATA", str(raw))
    monkeypatch.setattr(parallel.core, "LOGS", str(logs))
    monkeypatch.setattr(parallel, "CLEANED_LEDGER", str(logs / "cleaned_sources.txt"))
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

    rec_1 = ("A first source record with enough descriptive prose to pass the "
             "anomaly gate and land in the cleaned corpus for source one here.")
    rec_2 = ("A second source record, also long enough to survive the cleaning "
             "pipeline and remain in the corpus, belonging to source two here.")
    _write_jsonl(str(raw / "DomA" / "s1" / "a.jsonl"), [{"text": rec_1}])
    _write_jsonl(str(raw / "DomA" / "s2" / "b.jsonl"), [{"text": rec_2}])
    return raw


def test_run_clean_row_level_cleans_only_chosen_source(tmp_path, monkeypatch):
    raw = _wire_two_sources_one_domain(monkeypatch, tmp_path)
    clean_dir = tmp_path / "clean"
    # a pre-existing cleaned artifact for s2 that a row-level clean of s1 must keep
    preexisting = clean_dir / "DomA" / "s2" / "kept.jsonl"
    os.makedirs(os.path.dirname(preexisting), exist_ok=True)
    preexisting.write_text('{"kept": true}\n', encoding="utf-8")

    result = parallel.run_clean(sources_only=["DomA/s1"], keep_raw=True)

    assert result["files"] == 1                      # only s1 cleaned
    assert (clean_dir / "DomA" / "s1").is_dir()      # s1 cleaned output written
    assert preexisting.exists()                      # s2 cleaned output preserved
    assert (raw / "DomA" / "s2").is_dir()            # s2 raw untouched
    pipeline.reset_cleaner_cache()


def test_run_clean_row_level_purge_raw_deletes_only_chosen_source(tmp_path, monkeypatch):
    raw = _wire_two_sources_one_domain(monkeypatch, tmp_path)
    parallel.run_clean(sources_only=["DomA/s1"], keep_raw=False)
    assert not (raw / "DomA" / "s1").exists()        # chosen source raw purged
    assert (raw / "DomA" / "s2").is_dir()            # sibling source preserved
    pipeline.reset_cleaner_cache()
