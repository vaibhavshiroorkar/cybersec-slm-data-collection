"""run_ingest fetches all sources to data/raw/ and never cleans (ingest stage)."""

from __future__ import annotations

from concurrent.futures import Future

from cybersec_slm.ingestion import parallel


class _InlineExecutor:
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


def _wire(monkeypatch, tmp_path):
    monkeypatch.setattr(parallel, "COMPLETED_LEDGER", str(tmp_path / "led.txt"))
    monkeypatch.setattr(parallel, "ProcessPoolExecutor", _InlineExecutor)
    monkeypatch.setattr(parallel.ingestion_run, "show_table", lambda: None)
    monkeypatch.setattr(parallel, "_wipe_dir", lambda p: None)

    descriptors = [{"kind": "url", "url": u, "domain": "D", "license": "",
                    "description": ""} for u in ("http://a", "http://b")]
    monkeypatch.setattr(parallel.sources, "load_descriptors",
                        lambda spec=None: descriptors)

    class _Log:
        def record_many(self, rows):
            pass
    monkeypatch.setattr(parallel, "IngestLog", _Log)

    seen_clean: list = []

    def _proc(descriptor, *, data_root=None, limit=None, clean=True):
        seen_clean.append(clean)
        # fetch-only: create the raw folder and leave it in place.
        folder = tmp_path / "raw" / descriptor["url"].replace("://", "_")
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "data.jsonl").write_text('{"text":"x"}\n', encoding="utf-8")
        return {"status": "ok", "folder": str(folder), "ingest_rows": [],
                "light_eda_report": {}, "flags": {}, "clean_rows": []}

    monkeypatch.setattr(parallel.worker, "process_source", _proc)
    return seen_clean


def test_ingest_fetches_all_keeps_raw_and_never_cleans(tmp_path, monkeypatch):
    seen_clean = _wire(monkeypatch, tmp_path)
    result = parallel.run_ingest(resume=False)

    assert result["ok"] == 2
    # the worker was always driven fetch-only
    assert seen_clean == [False, False]
    # raw folders are retained for the clean stage
    raw = tmp_path / "raw"
    assert (raw / "http_a").is_dir()
    assert (raw / "http_b").is_dir()
    # both sources recorded in the resume ledger
    ledger = tmp_path / "led.txt"
    assert len([ln for ln in ledger.read_text(encoding="utf-8").splitlines() if ln]) == 2
    # no clean report written by the ingest stage
    assert "clean_rows" in result and result["clean_rows"] == []


def test_ingest_resume_skips_already_fetched(tmp_path, monkeypatch):
    _wire(monkeypatch, tmp_path)
    from cybersec_slm.ingestion.sources import descriptor_key
    key = descriptor_key({"kind": "url", "url": "http://a", "domain": "D"})
    (tmp_path / "led.txt").write_text(key + "\n", encoding="utf-8")

    result = parallel.run_ingest(resume=True)
    assert result["ok"] == 1        # only http://b is fetched
