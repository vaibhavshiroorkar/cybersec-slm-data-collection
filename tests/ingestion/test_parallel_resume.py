"""Resume ledger + skip logic for the parallel ingestion driver.

Uses an inline (synchronous, in-process) executor so the resume behaviour can be
tested without spawning processes or hitting the network.

v2: tests target ``run_parallel_ingest`` (the v2 phase 1 function).
The legacy ``run_streaming_legacy`` tests are preserved for backward compat.
"""

import os
from concurrent.futures import Future

from cybersec_slm.ingestion import parallel


class _InlineExecutor:
    """Synchronous stand-in: submit runs now and returns a completed Future."""
    _processes: dict = {}

    def __init__(self, *a, **k):
        pass

    def submit(self, fn, *args, **kwargs):
        fut = Future()
        try:
            fut.set_result(fn(*args, **kwargs))
        except Exception as e:  # noqa: BLE001
            fut.set_exception(e)
        return fut

    def shutdown(self, *a, **k):
        pass


def _descriptors():
    return [
        {"kind": "url", "url": "http://example.com/a", "domain": "D",
         "license": "", "description": ""},
        {"kind": "url", "url": "http://example.com/b", "domain": "D",
         "license": "", "description": ""},
    ]


def _install(monkeypatch, ledger_path):
    """Wire an inline executor and neutralize side-effecting collaborators."""
    calls: list[str] = []
    monkeypatch.setattr(parallel, "COMPLETED_LEDGER", str(ledger_path))
    monkeypatch.setattr(parallel, "ProcessPoolExecutor", _InlineExecutor)
    monkeypatch.setattr(parallel.cleaning_pipeline, "reset_dedup_state", lambda: None)
    monkeypatch.setattr(parallel.cleaning_pipeline, "_cleaner", lambda f: object())
    monkeypatch.setattr(parallel.cleaning_pipeline, "_write_report", lambda rows: "")
    monkeypatch.setattr(parallel.cleaning_pipeline, "clean_source_folder",
                        lambda folder, **kw: [{"file": folder, "in": 0, "out": 0}])
    monkeypatch.setattr(parallel, "_wipe_dir", lambda p: None)
    monkeypatch.setattr(parallel.shutil, "rmtree", lambda p, **k: None)
    monkeypatch.setattr(parallel.ingestion_run, "show_table", lambda: None)
    monkeypatch.setattr(parallel.sources, "load_descriptors",
                        lambda spec=None, **kw: _descriptors())

    class _DummyLog:
        def record(self, **kw):
            pass

        def record_many(self, rows):
            pass

    monkeypatch.setattr(parallel, "IngestLog", _DummyLog)

    def _stub_process(descriptor, **kwargs):
        calls.append(parallel.descriptor_key(descriptor))
        return {"status": "ok", "folder": None, "ingest_rows": [],
                "light_eda_report": {}, "flags": {}}

    monkeypatch.setattr(parallel.worker, "process_source", _stub_process)
    return calls


def test_ledger_helpers(tmp_path):
    p = str(tmp_path / "led.txt")
    assert parallel._load_completed(p) == set()
    with open(p, "w", encoding="utf-8") as f:
        f.write("k1\n\n  k2  \n")
    assert parallel._load_completed(p) == {"k1", "k2"}
    parallel._reset_completed(p)
    assert not os.path.exists(p)
    parallel._reset_completed(p)      # idempotent: no error when already gone


def test_fresh_run_records_all_and_resets_ledger(tmp_path, monkeypatch):
    ledger = tmp_path / "completed.txt"
    ledger.write_text("stale:key\n", encoding="utf-8")   # must be wiped on a fresh run
    calls = _install(monkeypatch, ledger)

    parallel.run_ingest(resume=False)

    assert set(calls) == {"http://example.com/a", "http://example.com/b"}
    assert parallel._load_completed(str(ledger)) == {
        "http://example.com/a", "http://example.com/b"}   # stale entry gone


def test_resume_skips_completed_sources(tmp_path, monkeypatch):
    ledger = tmp_path / "completed.txt"
    ledger.write_text("http://example.com/a\n", encoding="utf-8")   # 'a' already done
    calls = _install(monkeypatch, ledger)

    parallel.run_ingest(resume=True)

    assert calls == ["http://example.com/b"]              # only the missing source ran
    assert parallel._load_completed(str(ledger)) == {
        "http://example.com/a", "http://example.com/b"}


def test_timeout_break_preserves_unsubmitted_descriptors(tmp_path, monkeypatch):
    """A round that ends early (timeout) must not drop descriptors still queued
    behind the hung one -- regression test for the pending_iter-drain bug where
    only in-flight futures were re-queued and anything not yet pulled from the
    round's local iterator vanished silently (never fetched, never logged).
    """
    descriptors = [
        {"kind": "url", "url": "http://example.com/hang", "domain": "D",
         "license": "", "description": ""},
        {"kind": "url", "url": "http://example.com/a", "domain": "D",
         "license": "", "description": ""},
        {"kind": "url", "url": "http://example.com/b", "domain": "D",
         "license": "", "description": ""},
    ]

    class _HangOnceExecutor:
        """Like _InlineExecutor, but the 'hang' descriptor's future never resolves
        (simulates a worker that never returns, forcing the timeout path)."""
        _processes: dict = {}
        hung: set = {"http://example.com/hang"}

        def __init__(self, *a, **k):
            pass

        def submit(self, fn, descriptor, **kwargs):
            fut = Future()
            key = parallel.descriptor_key(descriptor)
            if key in _HangOnceExecutor.hung:
                _HangOnceExecutor.hung.discard(key)   # only hang once
                return fut                            # left pending forever
            try:
                fut.set_result(fn(descriptor, **kwargs))
            except Exception as e:  # noqa: BLE001
                fut.set_exception(e)
            return fut

        def shutdown(self, *a, **k):
            pass

    class _FakeClock:
        """Deterministic stand-in for time.monotonic(): advances by a fixed step
        on every call so the overdue check fires predictably without real sleeps."""

        def __init__(self, step=0.1):
            self.t = 0.0
            self.step = step

        def __call__(self):
            self.t += self.step
            return self.t

    ledger = tmp_path / "completed.txt"
    calls: list[str] = []
    monkeypatch.setattr(parallel, "COMPLETED_LEDGER", str(ledger))
    monkeypatch.setattr(parallel, "ProcessPoolExecutor", _HangOnceExecutor)
    monkeypatch.setattr(parallel, "POLL_INTERVAL_S", 0.01)
    monkeypatch.setattr(parallel, "_now", _FakeClock(step=0.1))
    monkeypatch.setattr(parallel.cleaning_pipeline, "reset_dedup_state", lambda: None)
    monkeypatch.setattr(parallel.cleaning_pipeline, "_write_report", lambda rows: "")
    monkeypatch.setattr(parallel, "_wipe_dir", lambda p: None)
    monkeypatch.setattr(parallel.shutil, "rmtree", lambda p, **k: None)
    monkeypatch.setattr(parallel.ingestion_run, "show_table", lambda: None)
    monkeypatch.setattr(parallel.sources, "load_descriptors",
                        lambda spec=None, **kw: descriptors)

    class _DummyLog:
        def record(self, **kw):
            pass

        def record_many(self, rows):
            pass

    monkeypatch.setattr(parallel, "IngestLog", _DummyLog)

    def _stub_process(descriptor, **kwargs):
        calls.append(parallel.descriptor_key(descriptor))
        return {"status": "ok", "folder": None, "ingest_rows": [],
                "light_eda_report": {}, "flags": {}}

    monkeypatch.setattr(parallel.worker, "process_source", _stub_process)

    summary = parallel.run_ingest(workers=1, resume=False, source_timeout=1.0)

    # The hung descriptor never actually invokes the worker; the two behind it
    # in the queue must still be picked up on the rebuilt round instead of
    # disappearing with no record anywhere.
    assert set(calls) == {"http://example.com/a", "http://example.com/b"}
    assert summary["ok"] == 2
    assert summary["failed"] == 1
    assert summary["timed_out"] == 1
    assert parallel._load_completed(str(ledger)) == {
        "http://example.com/a", "http://example.com/b"}


def test_resume_all_complete_short_circuits(tmp_path, monkeypatch):
    ledger = tmp_path / "completed.txt"
    ledger.write_text("http://example.com/a\nhttp://example.com/b\n", encoding="utf-8")
    calls = _install(monkeypatch, ledger)

    result = parallel.run_ingest(resume=True)

    assert calls == []                                    # nothing re-fetched
    assert result.get("all_done") is True                 # short-circuited
