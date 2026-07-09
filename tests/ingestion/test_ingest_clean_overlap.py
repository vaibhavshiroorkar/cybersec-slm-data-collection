"""run_ingest_clean fetches in parallel and cleans each source inline."""
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


def _wire(monkeypatch, tmp_path, statuses):
    """statuses: dict descriptor-url -> status returned by the worker."""
    monkeypatch.setattr(parallel, "COMPLETED_LEDGER", str(tmp_path / "led.txt"))
    monkeypatch.setattr(parallel, "ProcessPoolExecutor", _InlineExecutor)
    monkeypatch.setattr(parallel.ingestion_run, "show_table", lambda: None)
    monkeypatch.setattr(parallel.cleaning_pipeline, "reset_dedup_state", lambda: None)

    monkeypatch.setattr(parallel.cleaning_pipeline, "_write_report", lambda rows: "")
    monkeypatch.setattr(parallel, "_wipe_dir", lambda p: None)
    descriptors = [{"kind": "url", "url": u, "domain": "D", "license": "",
                    "description": ""} for u in statuses]
    monkeypatch.setattr(parallel.sources, "load_descriptors",
                        lambda spec=None: descriptors)

    class _Log:
        def record_many(self, rows):
            pass
    monkeypatch.setattr(parallel, "IngestLog", _Log)

    cleaned: list[str] = []

    def _proc(descriptor, **kwargs):
        u = descriptor["url"]
        status = statuses[u]
        folder = f"/raw/{u}"
        res = {"status": status, "folder": folder, "ingest_rows": [],
               "light_eda_report": {}, "flags": {}}
        if status == "ok":
            cleaned.append(folder)
            res["clean_rows"] = [{"file": folder, "in": 1, "out": 1}]
        return res
    monkeypatch.setattr(parallel.worker, "process_source", _proc)
    return cleaned


def test_ok_sources_are_cleaned_inline(tmp_path, monkeypatch):
    cleaned = _wire(monkeypatch, tmp_path,
                    {"http://a": "ok", "http://b": "ok"})
    result = parallel.run_ingest_clean(resume=False)
    assert result["ok"] == 2
    assert sorted(cleaned) == ["/raw/http://a", "/raw/http://b"]
    assert result["clean_rows"] and len(result["clean_rows"]) == 2


def test_rejected_source_not_cleaned(tmp_path, monkeypatch):
    cleaned = _wire(monkeypatch, tmp_path,
                    {"http://a": "ok", "http://b": "rejected"})
    result = parallel.run_ingest_clean(resume=False)
    assert result["ok"] == 1
    assert result["rejected"] == 1
    assert cleaned == ["/raw/http://a"]     # rejected source is never cleaned
