"""_run_pool drives the pool generically: submit + on_result, no fetch/clean logic."""

from __future__ import annotations

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


def test_run_pool_processes_all_descriptors(monkeypatch):
    monkeypatch.setattr(parallel, "ProcessPoolExecutor", _InlineExecutor)
    descriptors = [{"kind": "url", "url": u} for u in ("a", "b", "c")]
    seen: list[str] = []
    summary = {"failed": 0, "timed_out": 0}

    def submit(pool, d):
        return pool.submit(lambda dd: {"status": "ok", "url": dd["url"]}, d)

    def on_result(d, meta):
        seen.append(meta["url"])
        return True

    parallel._run_pool(descriptors, submit=submit, on_result=on_result,
                       workers=2, source_timeout=1000.0, summary=summary)

    assert sorted(seen) == ["a", "b", "c"]
    assert summary["failed"] == 0


def test_run_pool_retries_then_fails_on_unknown_status(monkeypatch):
    monkeypatch.setattr(parallel, "ProcessPoolExecutor", _InlineExecutor)
    descriptors = [{"kind": "url", "url": "a", "domain": "D"}]
    summary = {"failed": 0, "timed_out": 0}

    def submit(pool, d):
        return pool.submit(lambda dd: {"status": "failed"}, d)

    def on_result(d, meta):
        return False   # always "failed" -> runner retries up to the cap, then fails

    parallel._run_pool(descriptors, submit=submit, on_result=on_result,
                       workers=1, source_timeout=1000.0, summary=summary)

    assert summary["failed"] == 1
