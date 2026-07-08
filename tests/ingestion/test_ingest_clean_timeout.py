"""A source exceeding source_timeout is abandoned; the run still completes."""
import itertools
from concurrent.futures import Future

from cybersec_slm.ingestion import parallel


class _HangExecutor:
    """submit for the 'hang' url returns a never-completing Future."""
    _processes: dict = {}

    def __init__(self, *a, **k):
        pass

    def submit(self, fn, *args, **kwargs):
        descriptor = args[0]
        if descriptor.get("url") == "http://hang":
            return Future()          # never resolved -> looks stuck
        fut = Future()
        fut.set_result(fn(*args, **kwargs))
        return fut

    def shutdown(self, *a, **k):
        pass


def test_timed_out_source_is_failed_and_run_completes(tmp_path, monkeypatch):
    monkeypatch.setattr(parallel, "COMPLETED_LEDGER", str(tmp_path / "led.txt"))
    monkeypatch.setattr(parallel, "ProcessPoolExecutor", _HangExecutor)
    monkeypatch.setattr(parallel.ingestion_run, "show_table", lambda: None)
    monkeypatch.setattr(parallel.cleaning_pipeline, "reset_dedup_state", lambda: None)
    monkeypatch.setattr(parallel.cleaning_pipeline, "_cleaner", lambda f: object())
    monkeypatch.setattr(parallel.cleaning_pipeline, "_write_report", lambda rows: "")
    monkeypatch.setattr(parallel.cleaning_pipeline, "clean_source_folder",
                        lambda folder, **kw: [])
    monkeypatch.setattr(parallel, "_wipe_dir", lambda p: None)
    monkeypatch.setattr(parallel.shutil, "rmtree", lambda p, **k: None)

    # wait() never reports the hung future as done; return nothing-done fast.
    monkeypatch.setattr(parallel, "wait",
                        lambda fs, timeout=None, return_when=None: (set(), set(fs)))
    # monotonic clock that jumps forward each call -> the sweep sees "overdue".
    counter = itertools.count()
    monkeypatch.setattr(parallel, "_now", lambda: float(next(counter)))

    class _Log:
        def record_many(self, rows):
            pass
    monkeypatch.setattr(parallel, "IngestLog", _Log)
    monkeypatch.setattr(parallel.sources, "load_descriptors", lambda spec=None: [
        {"kind": "url", "url": "http://hang", "domain": "D", "license": "",
         "description": ""}])

    def _proc(descriptor, **kwargs):
        return {"status": "ok", "folder": None, "ingest_rows": [],
                "light_eda_report": {}, "flags": {}}
    monkeypatch.setattr(parallel.worker, "process_source", _proc)

    result = parallel.run_ingest_clean(resume=False, source_timeout=0.0)
    assert result["timed_out"] == 1
    assert result["failed"] == 1
    assert result["ok"] == 0


def test_broken_pool_rebuilds_then_gives_up(tmp_path, monkeypatch):
    from concurrent.futures.process import BrokenProcessPool

    class _BrokenExecutor:
        _processes: dict = {}

        def __init__(self, *a, **k):
            pass

        def submit(self, fn, *args, **kwargs):
            fut = Future()
            fut.set_exception(BrokenProcessPool("boom"))
            return fut

        def shutdown(self, *a, **k):
            pass

    monkeypatch.setattr(parallel, "COMPLETED_LEDGER", str(tmp_path / "led.txt"))
    monkeypatch.setattr(parallel, "ProcessPoolExecutor", _BrokenExecutor)
    monkeypatch.setattr(parallel.ingestion_run, "show_table", lambda: None)
    monkeypatch.setattr(parallel.cleaning_pipeline, "reset_dedup_state", lambda: None)
    monkeypatch.setattr(parallel.cleaning_pipeline, "_cleaner", lambda f: object())
    monkeypatch.setattr(parallel.cleaning_pipeline, "_write_report", lambda rows: "")
    monkeypatch.setattr(parallel, "_wipe_dir", lambda p: None)

    class _Log:
        def record_many(self, rows):
            pass
    monkeypatch.setattr(parallel, "IngestLog", _Log)
    monkeypatch.setattr(parallel.sources, "load_descriptors", lambda spec=None: [
        {"kind": "url", "url": "http://x", "domain": "D", "license": "",
         "description": ""}])
    monkeypatch.setattr(parallel.worker, "process_source",
                        lambda d, **k: {"status": "ok"})

    result = parallel.run_ingest_clean(resume=False)
    assert result["failed"] == 1        # rebuilt MAX_POOL_REBUILDS times, then gave up
    assert result["ok"] == 0
