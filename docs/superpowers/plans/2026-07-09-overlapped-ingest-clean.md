# Overlapped Ingest + Sequential Clean — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clean each source sequentially in the parent process as soon as it finishes fetching, while other sources keep fetching in parallel worker processes, with a per-source timeout so one hung source can't stall the run.

**Architecture:** A `ProcessPoolExecutor` of fetch-only workers (fetch + light-EDA) is the producer; the parent consumes each finished source via `concurrent.futures.wait(..., FIRST_COMPLETED)` and cleans it inline with heavy models loaded once, deduper disabled. After the pool drains, one deterministic sorted global dedup pass runs, then EDA, then normalize.

**Tech Stack:** Python 3.10+, `concurrent.futures` (ProcessPoolExecutor, wait), `multiprocessing` spawn context, pytest.

## Global Constraints

- Windows/`win32` primary platform; use `mp.get_context("spawn")`.
- No third-party additions — stdlib `concurrent.futures` only for the driver.
- Per-source cleaning MUST use `Deduper(enabled=False)`; cross-source dedup is deferred to `final_global_dedup` (deterministic, sorted).
- Default per-source timeout: `1800.0` seconds. Pool-rebuild cap: `2`. Per-source retry cap: `1`. Wait poll interval: `10.0` seconds.
- Fresh (non-`--resume`) run wipes `data/clean/` and `data/raw/`; `--resume` leaves them intact.
- Commit messages: no Claude attribution / co-author trailer.
- Data layout preserved: `data/raw/<Sub-Domain>/<source>/<file>.jsonl` → mirrored under `data/clean/`.

---

### Task 1: `clean_source_folder` — clean one fetched source (O(files), dedup off)

**Files:**
- Modify: `src/cybersec_slm/cleaning/pipeline.py` (add function near `clean_one_source`, ~line 192)
- Test: `tests/cleaning/test_clean_source_folder.py` (create)

**Interfaces:**
- Consumes: `clean_files(files, *, deduper, redactor, langf, translator, out_cleaned, out_flagged, out_dropped, limit)`, `find_input_files`, `Deduper` — all already in `pipeline.py`.
- Produces: `clean_source_folder(folder, *, redactor, langf, translator, raw_root=RAW_DATA, clean_data_dir=OUT_CLEAN_DATA, flagged_dir=OUT_FLAGGED, dropped_dir=OUT_DROPPED, limit=None) -> list[dict]` — report rows (same shape `clean_files` returns).

- [ ] **Step 1: Write the failing test**

Create `tests/cleaning/test_clean_source_folder.py`:

```python
"""clean_source_folder cleans one source folder, dedup disabled, O(files)."""
import json
import os

from cybersec_slm.cleaning import pipeline


class _StubRedactor:
    def redact(self, text):
        return text, 0


class _StubLang:
    def detect(self, text):
        return "en"

    def lang_allowed(self, lang):
        return True


class _StubTranslator:
    def translate(self, text, src=None):
        return text, True


def _write_jsonl(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def test_cleans_only_its_own_folder_and_mirrors_layout(tmp_path):
    raw = tmp_path / "raw"
    clean = tmp_path / "clean"
    # target source
    _write_jsonl(str(raw / "Malware" / "srcA" / "a.jsonl"),
                 [{"text": "hello world one"}, {"text": "hello world two"}])
    # a DIFFERENT source that must be left untouched
    _write_jsonl(str(raw / "Network" / "srcB" / "b.jsonl"),
                 [{"text": "should not be touched"}])

    rows = pipeline.clean_source_folder(
        str(raw / "Malware" / "srcA"),
        redactor=_StubRedactor(), langf=_StubLang(), translator=_StubTranslator(),
        raw_root=str(raw), clean_data_dir=str(clean),
        flagged_dir=str(tmp_path / "flagged"), dropped_dir=str(tmp_path / "dropped"))

    # output mirrors the data/raw layout under clean/
    out = clean / "Malware" / "srcA" / "a.jsonl"
    assert out.exists()
    assert out.read_text(encoding="utf-8").count("\n") == 2
    # srcB was never cleaned (folder scan is scoped)
    assert not (clean / "Network").exists()
    assert rows and rows[0]["file"] == "Malware/srcA/a.jsonl"
    assert rows[0]["out"] == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/cleaning/test_clean_source_folder.py -v`
Expected: FAIL with `AttributeError: module 'cybersec_slm.cleaning.pipeline' has no attribute 'clean_source_folder'`

- [ ] **Step 3: Write minimal implementation**

In `src/cybersec_slm/cleaning/pipeline.py`, add after `clean_one_source` (before `reset_dedup_state`):

```python
def clean_source_folder(folder: str, *, redactor, langf, translator,
                        raw_root: str = RAW_DATA,
                        clean_data_dir: str = OUT_CLEAN_DATA,
                        flagged_dir: str = OUT_FLAGGED,
                        dropped_dir: str = OUT_DROPPED,
                        limit: int | None = None) -> list[dict]:
    """Clean ONE already-fetched source folder into data/clean/ (dedup disabled).

    Scans only `folder` (O(files-in-source), not the whole raw tree) but computes
    `rel` relative to `raw_root` so the data/clean/ layout mirrors data/raw/.
    The caller supplies the (once-built) transformers so the heavy models load a
    single time in the parent. Cross-source global dedup is deferred to
    `final_global_dedup`, so the deduper here is disabled. Returns report rows.
    """
    folder = os.path.abspath(folder)
    raw_root = os.path.abspath(raw_root)
    files: list[tuple[str, str, str, str]] = []
    for ap, _sub, _source, _rel in find_input_files(folder):
        rel = os.path.relpath(ap, raw_root).replace("\\", "/")
        parts = rel.split("/")
        sub = parts[0] if parts else "unknown"
        source = parts[1] if len(parts) > 2 else (parts[0] if parts else "unknown")
        files.append((ap, sub, source, rel))
    if not files:
        return []
    deduper = Deduper(enabled=False)
    return clean_files(files, deduper=deduper, redactor=redactor, langf=langf,
                       translator=translator, out_cleaned=clean_data_dir,
                       out_flagged=flagged_dir, out_dropped=dropped_dir, limit=limit)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/cleaning/test_clean_source_folder.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybersec_slm/cleaning/pipeline.py tests/cleaning/test_clean_source_folder.py
git commit -m "feat(cleaning): add clean_source_folder (per-source, O(files), dedup off)"
```

---

### Task 2: `run_ingest_clean` driver — overlapped fetch + inline clean

**Files:**
- Modify: `src/cybersec_slm/ingestion/parallel.py` (add module constants + `_now`, `_wipe_dir`, `_empty_summary`, `run_ingest_clean`; keep old functions for now)
- Test: `tests/ingestion/test_parallel_resume.py` (retarget to `run_ingest_clean`)
- Test: `tests/ingestion/test_ingest_clean_overlap.py` (create)

**Interfaces:**
- Consumes: `worker.process_source(descriptor, *, data_root)` → `{status, folder, ingest_rows, light_eda_report, flags}`; `cleaning_pipeline.clean_source_folder(...)` (Task 1); `cleaning_pipeline._cleaner(factory)`, `cleaning_pipeline._write_report(rows)`, `cleaning_pipeline.reset_dedup_state()`; `sources.load_descriptors`, `descriptor_key`, `IngestLog`, `ingestion_run.show_table`.
- Produces: `run_ingest_clean(spec=None, *, workers=None, resume=False, keep_raw=False, limit=None) -> dict` with keys `ok, failed, skipped, rejected, timed_out, ingest_rows, light_eda_reports, flags, clean_rows` (and `all_done: True` on a fully-resumed no-op). Module attrs `POLL_INTERVAL_S`, `MAX_POOL_REBUILDS`, `MAX_SOURCE_RETRIES`, `_now`, `wait`, `FIRST_COMPLETED`, `BrokenProcessPool`.

- [ ] **Step 1: Write the failing overlap test**

Create `tests/ingestion/test_ingest_clean_overlap.py`:

```python
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
    monkeypatch.setattr(parallel.cleaning_pipeline, "_cleaner", lambda f: object())
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

    def _clean(folder, **kw):
        cleaned.append(folder)
        return [{"file": folder, "in": 1, "out": 1}]
    monkeypatch.setattr(parallel.cleaning_pipeline, "clean_source_folder", _clean)
    monkeypatch.setattr(parallel.shutil, "rmtree", lambda p, **k: None)

    def _proc(descriptor, **kwargs):
        u = descriptor["url"]
        return {"status": statuses[u], "folder": f"/raw/{u}", "ingest_rows": [],
                "light_eda_report": {}, "flags": {}}
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/ingestion/test_ingest_clean_overlap.py -v`
Expected: FAIL with `AttributeError: module 'cybersec_slm.ingestion.parallel' has no attribute 'run_ingest_clean'`

- [ ] **Step 3: Add imports, constants, and helpers to `parallel.py`**

At the top of `src/cybersec_slm/ingestion/parallel.py`, update imports:

```python
import multiprocessing as mp
import os
import shutil
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from concurrent.futures.process import BrokenProcessPool

from .. import core
from ..cleaning import pipeline as cleaning_pipeline
from . import run as ingestion_run
from . import sources, worker
from .common import IngestLog, logger
from .sources import descriptor_key
```

Add constants below `COMPLETED_LEDGER`:

```python
POLL_INTERVAL_S = 10.0           # wait() granularity for the consume loop
DEFAULT_SOURCE_TIMEOUT_S = 1800.0  # per-source wall-clock budget (30 min)
MAX_POOL_REBUILDS = 2            # bound pool restarts on timeout / broken pool
MAX_SOURCE_RETRIES = 1           # resubmit a transiently-failing source once


def _now() -> float:
    """Monotonic clock indirection (a test seam for the timeout sweep)."""
    return time.monotonic()


def _wipe_dir(path: str) -> None:
    """Remove a data tree so a fresh (non-resume) build starts clean."""
    shutil.rmtree(path, ignore_errors=True)


def _empty_summary() -> dict:
    return {"ok": 0, "failed": 0, "skipped": 0, "rejected": 0, "timed_out": 0,
            "ingest_rows": [], "light_eda_reports": [], "flags": [],
            "clean_rows": []}
```

- [ ] **Step 4: Write `run_ingest_clean`**

Add to `parallel.py` (after the helpers, replacing the `# Phase 1` section header):

```python
def run_ingest_clean(spec: str | None = None, *, workers: int | None = None,
                     resume: bool = False, keep_raw: bool = False,
                     limit: int | None = None,
                     source_timeout: float = DEFAULT_SOURCE_TIMEOUT_S) -> dict:
    """Fetch sources in parallel; clean each inline in the parent as it finishes.

    Producer: a spawn ProcessPoolExecutor of fetch-only workers.
    Consumer: this parent process cleans each "ok" source with `clean_source_folder`
    (deduper disabled, heavy models built once), deletes its raw folder unless
    `keep_raw`, and appends its key to the resume ledger. A source that raises is
    resubmitted once; a source exceeding `source_timeout` is abandoned (see the
    timeout sweep). Cross-source dedup runs later in `final_global_dedup`.
    """
    from ..cleaning.langfilter import LangFilter
    from ..cleaning.pii import Redactor
    from ..cleaning.translate import Translator

    os.environ["CYBERSEC_SLM_DATA_ROOT"] = core.DATA_ROOT
    descriptors = sources.load_descriptors(spec or sources.DEFAULT_CATALOG)
    if not descriptors:
        logger.warning("no sources to process")
        return _empty_summary()

    if resume:
        done_keys = _load_completed(COMPLETED_LEDGER)
        n_before = len(descriptors)
        descriptors = [d for d in descriptors if descriptor_key(d) not in done_keys]
        n_skip = n_before - len(descriptors)
        if n_skip:
            logger.info(f"resume: skipping {n_skip} already-complete sources "
                        f"({len(descriptors)} left to process)")
        if not descriptors:
            logger.info("resume: all sources already complete")
            return {**_empty_summary(), "all_done": True}
    else:
        _reset_completed(COMPLETED_LEDGER)
        cleaning_pipeline.reset_dedup_state()
        _wipe_dir(core.CLEAN_DATA)
        _wipe_dir(core.RAW_DATA)

    workers = workers or _default_workers()
    logger.info(f"ingest+clean: {len(descriptors)} sources, {workers} workers, "
                f"source_timeout={source_timeout:.0f}s -> {core.CLEAN_DATA}")

    # Heavy transformers built ONCE in the parent (reused across every source).
    redactor = cleaning_pipeline._cleaner(Redactor)
    langf = cleaning_pipeline._cleaner(LangFilter)
    translator = cleaning_pipeline._cleaner(Translator)

    ctx = mp.get_context("spawn")
    os.makedirs(core.LOGS, exist_ok=True)
    ledger = open(COMPLETED_LEDGER, "a", encoding="utf-8")

    log = IngestLog()
    summary = _empty_summary()
    retries: dict[str, int] = {}
    pending_descriptors = list(descriptors)
    rebuilds = 0

    def _label(d):
        return d.get("ref") or d.get("slug") or d.get("kind")

    def _clean_ok(d, meta):
        folder = meta.get("folder")
        if folder:
            rows = cleaning_pipeline.clean_source_folder(
                folder, redactor=redactor, langf=langf, translator=translator,
                limit=limit)
            summary["clean_rows"].extend(rows)
            if not keep_raw:
                shutil.rmtree(folder, ignore_errors=True)
        summary["ok"] += 1
        ledger.write(descriptor_key(d) + "\n"); ledger.flush()

    def _record(d, meta):
        summary["ingest_rows"].extend(meta.get("ingest_rows", []))
        leda = meta.get("light_eda_report", {})
        if leda:
            summary["light_eda_reports"].append(leda)
        flags = meta.get("flags", {})
        if flags:
            summary["flags"].append({"source": _label(d), **flags})
        status = meta.get("status")
        if status == "ok":
            _clean_ok(d, meta)
        elif status == "skipped":
            summary["skipped"] += 1
            ledger.write(descriptor_key(d) + "\n"); ledger.flush()
        elif status == "rejected":
            summary["rejected"] += 1
        else:
            return False   # unknown/"failed": caller decides retry vs fail
        return True

    try:
        while pending_descriptors and rebuilds <= MAX_POOL_REBUILDS:
            round_descriptors = pending_descriptors
            pending_descriptors = []
            pool = ProcessPoolExecutor(max_workers=workers, mp_context=ctx)
            started: dict = {}
            fut_desc: dict = {}
            remaining = set()

            def _submit(d):
                fut = pool.submit(worker.process_source, d, data_root=core.DATA_ROOT)
                started[fut] = _now()
                fut_desc[fut] = d
                remaining.add(fut)

            for d in round_descriptors:
                _submit(d)

            def _fail_or_retry(d):
                k = descriptor_key(d)
                if retries.get(k, 0) < MAX_SOURCE_RETRIES:
                    retries[k] = retries.get(k, 0) + 1
                    _submit(d)                 # resubmit into the SAME live pool
                else:
                    summary["failed"] += 1

            broke = timed_out = False
            try:
                while remaining:
                    done, _pend = wait(remaining, timeout=POLL_INTERVAL_S,
                                       return_when=FIRST_COMPLETED)
                    for fut in done:
                        remaining.discard(fut)
                        d = fut_desc[fut]
                        try:
                            meta = fut.result()
                        except BrokenProcessPool:
                            raise
                        except Exception as ex:
                            logger.error(f"  worker crashed for {_label(d)}: "
                                         f"{type(ex).__name__}: {ex}")
                            _fail_or_retry(d)
                            continue
                        if not _record(d, meta):
                            logger.warning(f"  FAILED {_label(d)}: "
                                           f"{meta.get('error')}")
                            _fail_or_retry(d)
                    now = _now()
                    overdue = [f for f in remaining
                               if now - started[f] > source_timeout]
                    if overdue:
                        for f in overdue:
                            logger.error(f"  TIMEOUT {_label(fut_desc[f])}: exceeded "
                                         f"{source_timeout:.0f}s; abandoning")
                            summary["timed_out"] += 1
                            summary["failed"] += 1
                            remaining.discard(f)
                        pending_descriptors.extend(fut_desc[f] for f in remaining)
                        timed_out = True
                        break
            except BrokenProcessPool as ex:
                logger.error(f"process pool broke: {ex}")
                pending_descriptors.extend(fut_desc[f] for f in remaining)
                broke = True
            finally:
                _force_shutdown(pool)

            if timed_out or broke:
                rebuilds += 1
                if rebuilds > MAX_POOL_REBUILDS and pending_descriptors:
                    logger.error(f"  giving up on {len(pending_descriptors)} sources "
                                 f"after {MAX_POOL_REBUILDS} pool rebuilds")
                    summary["failed"] += len(pending_descriptors)
                    pending_descriptors = []
    finally:
        ledger.close()

    log.record_many(summary["ingest_rows"])
    if summary["clean_rows"]:
        cleaning_pipeline._write_report(summary["clean_rows"])
    ingestion_run.show_table()
    logger.info(f"ingest+clean done: ok={summary['ok']} failed={summary['failed']} "
                f"skipped={summary['skipped']} rejected={summary['rejected']} "
                f"timed_out={summary['timed_out']}")
    return summary


def _force_shutdown(pool) -> None:
    """Shut a pool down without waiting, terminating any leaked/hung workers."""
    try:
        pool.shutdown(wait=False, cancel_futures=True)
    except Exception:
        pass
    for p in list(getattr(pool, "_processes", {}).values() or []):
        try:
            p.terminate()
        except Exception:
            pass
```

- [ ] **Step 5: Run the overlap test**

Run: `python -m pytest tests/ingestion/test_ingest_clean_overlap.py -v`
Expected: PASS (both tests)

- [ ] **Step 6: Retarget the resume tests**

In `tests/ingestion/test_parallel_resume.py`, replace `_install` and the three `run_parallel_ingest` tests so they target `run_ingest_clean`. Replace the `_InlineExecutor`/`_InlineFuture` classes and `_install` with:

```python
from concurrent.futures import Future


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


def _install(monkeypatch, ledger_path):
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
                        lambda spec=None: _descriptors())

    class _DummyLog:
        def record_many(self, rows):
            pass
    monkeypatch.setattr(parallel, "IngestLog", _DummyLog)

    def _stub_process(descriptor, **kwargs):
        calls.append(parallel.descriptor_key(descriptor))
        return {"status": "ok", "folder": None, "ingest_rows": [],
                "light_eda_report": {}, "flags": {}}
    monkeypatch.setattr(parallel.worker, "process_source", _stub_process)
    return calls
```

Then in `test_fresh_run_records_all_and_resets_ledger`, `test_resume_skips_completed_sources`, and `test_resume_all_complete_short_circuits`, replace `parallel.run_parallel_ingest(` with `parallel.run_ingest_clean(`. Leave `test_ledger_helpers` unchanged. In the fresh-run test the `calls` order is completion order; assert membership instead of order:

```python
    parallel.run_ingest_clean(resume=False)
    assert set(calls) == {"http://example.com/a", "http://example.com/b"}
    assert parallel._load_completed(str(ledger)) == {
        "http://example.com/a", "http://example.com/b"}
```

- [ ] **Step 7: Run the resume tests**

Run: `python -m pytest tests/ingestion/test_parallel_resume.py -v`
Expected: PASS (all four tests)

- [ ] **Step 8: Commit**

```bash
git add src/cybersec_slm/ingestion/parallel.py tests/ingestion/test_ingest_clean_overlap.py tests/ingestion/test_parallel_resume.py
git commit -m "feat(ingestion): overlapped fetch + inline sequential clean driver"
```

---

### Task 3: Per-source timeout sweep + capped pool rebuild

The sweep and rebuild logic is already present in Task 2's `run_ingest_clean` (the `overdue` block and the `while pending_descriptors and rebuilds <= MAX_POOL_REBUILDS` loop). This task adds the `source_timeout` parameter to the public entry (already in the signature) and proves the behavior with tests using the `_now` seam.

**Files:**
- Test: `tests/ingestion/test_ingest_clean_timeout.py` (create)

**Interfaces:**
- Consumes: `parallel.run_ingest_clean(..., source_timeout=...)`, `parallel._now`, `parallel.wait`.

- [ ] **Step 1: Write the failing timeout test**

Create `tests/ingestion/test_ingest_clean_timeout.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails (if signature/logic incomplete) or passes**

Run: `python -m pytest tests/ingestion/test_ingest_clean_timeout.py -v`
Expected: PASS if Task 2 was implemented exactly as written. If it FAILS with a hang or `TypeError: unexpected keyword 'source_timeout'`, fix `run_ingest_clean` per Task 2 Step 4 (ensure the `source_timeout` kwarg and the `overdue`/rebuild blocks exist).

- [ ] **Step 3: Add a broken-pool rebuild test**

Append to `tests/ingestion/test_ingest_clean_timeout.py`:

```python
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
```

- [ ] **Step 4: Run both timeout tests**

Run: `python -m pytest tests/ingestion/test_ingest_clean_timeout.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add tests/ingestion/test_ingest_clean_timeout.py
git commit -m "test(ingestion): cover per-source timeout + broken-pool rebuild"
```

---

### Task 4: Wire the pipeline, add `clean_raw_tree`, remove old phases, tidy worker/flows

**Files:**
- Modify: `src/cybersec_slm/ingestion/parallel.py` (rewrite `run_v2_pipeline`; add `clean_raw_tree`; delete `run_parallel_ingest` and `run_aggregated_clean`)
- Modify: `src/cybersec_slm/ingestion/worker.py` (drop unused `keep_raw`/`limit` params)
- Modify: `src/cybersec_slm/orchestration/flows.py` (clean step → `clean_raw_tree` + `final_global_dedup`)
- Modify: `tests/orchestration/test_flows.py` (adjust to the new clean task)
- Test: `tests/ingestion/test_v2_pipeline_wiring.py` (create)

**Interfaces:**
- Consumes: `run_ingest_clean` (Task 2); `cleaning_pipeline.final_global_dedup(clean_data_dir, *, resume)`; `cleaning_pipeline.clean_files`, `find_input_files`; `run_deep_eda`, `run_normalize`.
- Produces: `run_v2_pipeline(spec=None, *, workers=None, resume=False, keep_raw=False, limit=None, source_timeout=DEFAULT_SOURCE_TIMEOUT_S, enforce_eda=True, normalize=True) -> dict`; `clean_raw_tree(*, keep_raw=False, limit=None) -> dict`.

- [ ] **Step 1: Write the failing wiring test**

Create `tests/ingestion/test_v2_pipeline_wiring.py`:

```python
"""run_v2_pipeline calls ingest+clean -> final_global_dedup -> eda -> normalize."""
from cybersec_slm.ingestion import parallel


def test_pipeline_order(monkeypatch):
    order = []
    monkeypatch.setattr(parallel, "run_ingest_clean",
                        lambda *a, **k: order.append("ingest") or {"ok": 1})
    monkeypatch.setattr(parallel.cleaning_pipeline, "final_global_dedup",
                        lambda d, resume=False: order.append("dedup") or {"kept": 1})
    monkeypatch.setattr(parallel, "run_deep_eda",
                        lambda enforce=True: order.append("eda") or {"passed": True})
    monkeypatch.setattr(parallel, "run_normalize",
                        lambda resume=False: order.append("normalize") or {"n": 1})

    result = parallel.run_v2_pipeline(normalize=True)
    assert order == ["ingest", "dedup", "eda", "normalize"]
    assert result["phase"] == "complete"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/ingestion/test_v2_pipeline_wiring.py -v`
Expected: FAIL (`run_v2_pipeline` still calls `run_parallel_ingest`/`run_aggregated_clean`)

- [ ] **Step 3: Replace `run_v2_pipeline`, delete old phase functions, add `clean_raw_tree`**

In `parallel.py`, delete `run_parallel_ingest` and `run_aggregated_clean`. Keep `run_deep_eda` and `run_normalize`. Add `clean_raw_tree` and rewrite `run_v2_pipeline`:

```python
def clean_raw_tree(*, keep_raw: bool = False, limit: int | None = None) -> dict:
    """Clean the whole existing data/raw/ tree in one sequential pass (dedup off).

    Used by the Prefect flow, which fetches via its own mapped tasks and then
    needs a single clean pass. Deterministic cross-source dedup is left to
    `final_global_dedup`. The CLI uses `run_ingest_clean` (overlap) instead.
    """
    from ..cleaning.dedup import Deduper
    from ..cleaning.langfilter import LangFilter
    from ..cleaning.pii import Redactor
    from ..cleaning.translate import Translator

    files = list(cleaning_pipeline.find_input_files(core.RAW_DATA))
    if not files:
        logger.warning("clean_raw_tree: no raw data to clean")
        return {"files": 0, "in": 0, "out": 0}
    deduper = Deduper(enabled=False)
    redactor = cleaning_pipeline._cleaner(Redactor)
    langf = cleaning_pipeline._cleaner(LangFilter)
    translator = cleaning_pipeline._cleaner(Translator)
    rows = cleaning_pipeline.clean_files(
        files, deduper=deduper, redactor=redactor, langf=langf,
        translator=translator, out_cleaned=core.CLEAN_DATA,
        out_flagged=core.FLAGGED, out_dropped=core.DROPPED, limit=limit)
    if rows:
        cleaning_pipeline._write_report(rows)
    if not keep_raw:
        _wipe_dir(core.RAW_DATA)
    total_in = sum(r.get("in", 0) for r in rows)
    total_out = sum(r.get("out", 0) for r in rows)
    return {"files": len(rows), "in": total_in, "out": total_out}


def run_v2_pipeline(spec: str | None = None, *, workers: int | None = None,
                    resume: bool = False, keep_raw: bool = False,
                    limit: int | None = None,
                    source_timeout: float = DEFAULT_SOURCE_TIMEOUT_S,
                    enforce_eda: bool = True, normalize: bool = True) -> dict:
    """Overlapped ingest+clean -> deterministic dedup -> deep EDA -> normalize."""
    from ..eda import SufficiencyError

    ingest_result = run_ingest_clean(spec, workers=workers, resume=resume,
                                     keep_raw=keep_raw, limit=limit,
                                     source_timeout=source_timeout)
    dedup_result = cleaning_pipeline.final_global_dedup(core.CLEAN_DATA, resume=resume)

    try:
        eda_result = run_deep_eda(enforce=enforce_eda)
    except SufficiencyError as exc:
        logger.error(str(exc))
        print("Pipeline halted at the EDA sufficiency gate — "
              "address the blockers above and re-run.")
        return {"phase": "eda", "error": str(exc), "ingest": ingest_result,
                "dedup": dedup_result}

    norm_result = {}
    if normalize:
        norm_result = run_normalize(resume=resume)
    return {"phase": "complete", "ingest": ingest_result, "dedup": dedup_result,
            "eda": eda_result, "normalize": norm_result}
```

Also update the module docstring's phase description to reflect overlap (replace the "Phase 1 … Phase 2 … after the pool drains" block with a two-line summary: overlapped ingest+clean, then deterministic dedup → EDA → normalize).

- [ ] **Step 4: Run the wiring test**

Run: `python -m pytest tests/ingestion/test_v2_pipeline_wiring.py -v`
Expected: PASS

- [ ] **Step 5: Drop unused worker params**

In `src/cybersec_slm/ingestion/worker.py`, change the signature:

```python
def process_source(descriptor: dict, *, data_root: str | None = None) -> dict:
```

Remove `keep_raw: bool = False, limit: int | None = None` from the signature (they are unused in the v2 worker). Leave the body unchanged.

- [ ] **Step 6: Update the Prefect flow**

In `src/cybersec_slm/orchestration/flows.py`, replace the `aggregated_clean` task and its call. Change the task:

```python
@task
def aggregated_clean() -> dict:
    """Sequential clean of data/raw/ then deterministic cross-source dedup."""
    from ..ingestion.parallel import clean_raw_tree
    from ..cleaning.pipeline import final_global_dedup
    from ..core import CLEAN_DATA
    result = clean_raw_tree()
    final_global_dedup(CLEAN_DATA, resume=False)
    return result
```

(The `build_corpus` flow already calls `aggregated_clean()`; no change to the call site is needed.)

- [ ] **Step 7: Run the flows + full ingestion tests**

Run: `python -m pytest tests/orchestration/test_flows.py tests/ingestion -v`
Expected: PASS. If `test_flows.py` asserts on the old `run_aggregated_clean` import path, update that assertion to the new `clean_raw_tree` + `final_global_dedup` behavior (keep the test's intent: the clean task runs and returns a dict).

- [ ] **Step 8: Commit**

```bash
git add src/cybersec_slm/ingestion/parallel.py src/cybersec_slm/ingestion/worker.py src/cybersec_slm/orchestration/flows.py tests/ingestion/test_v2_pipeline_wiring.py tests/orchestration/test_flows.py
git commit -m "refactor(pipeline): wire overlapped ingest+clean; drop old two-phase funcs"
```

---

### Task 5: CLI `--source-timeout` for `run` and `all`

**Files:**
- Modify: `src/cybersec_slm/cli.py` (add flag to `run` + `all`, thread into `run_v2_pipeline`)
- Test: `tests/test_cli_source_timeout.py` (create)

**Interfaces:**
- Consumes: `build_parser()`; `parallel.run_v2_pipeline(..., source_timeout=...)`.
- Produces: `--source-timeout` (float, default 1800.0) on `run` and `all`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_cli_source_timeout.py`:

```python
from cybersec_slm.cli import build_parser


def test_run_has_source_timeout_default():
    args = build_parser().parse_args(["run"])
    assert args.source_timeout == 1800.0


def test_all_accepts_source_timeout():
    args = build_parser().parse_args(["all", "--source-timeout", "60"])
    assert args.source_timeout == 60.0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli_source_timeout.py -v`
Expected: FAIL with `AttributeError: 'Namespace' object has no attribute 'source_timeout'`

- [ ] **Step 3: Add the flag to both subparsers**

In `src/cybersec_slm/cli.py`, in the `run` subparser (after `--resume`):

```python
    r.add_argument("--source-timeout", type=float, default=1800.0,
                   help="per-source wall-clock timeout in seconds "
                        "(abandon a hung source; default 1800)")
```

In the `all` subparser (after `--limit`):

```python
    a.add_argument("--source-timeout", type=float, default=1800.0,
                   help="per-source wall-clock timeout in seconds "
                        "(abandon a hung source; default 1800)")
```

Thread it through both call sites in `main`:

```python
    elif args.stage == "run":
        from .ingestion import parallel
        parallel.run_v2_pipeline(args.sources,
                                 workers=args.workers,
                                 resume=args.resume,
                                 keep_raw=args.keep_raw,
                                 limit=args.limit,
                                 source_timeout=args.source_timeout,
                                 normalize=False)
```

```python
    elif args.stage == "all":
        if getattr(args, "no_auto_rebalance", False):
            from .eda import config as eda_config
            eda_config.AUTO_REBALANCE = False
        from .ingestion import parallel
        parallel.run_v2_pipeline(
            resume=args.resume,
            keep_raw=getattr(args, "keep_raw", False),
            limit=getattr(args, "limit", None),
            source_timeout=args.source_timeout,
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_cli_source_timeout.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybersec_slm/cli.py tests/test_cli_source_timeout.py
git commit -m "feat(cli): add --source-timeout to run and all"
```

---

### Task 6: Full-suite verification + docstring/help sweep

**Files:**
- Modify: `src/cybersec_slm/cli.py` (module docstring line for `run`), `src/cybersec_slm/ingestion/parallel.py` (docstring), as needed for accuracy.

- [ ] **Step 1: Run the whole test suite**

Run: `python -m pytest -q`
Expected: PASS (no failures). Investigate and fix any test that referenced the removed `run_parallel_ingest` / `run_aggregated_clean` or the old worker signature.

- [ ] **Step 2: Grep for stale references**

Run: `git grep -n "run_parallel_ingest\|run_aggregated_clean\|legacy-streaming\|run_streaming"`
Expected: no hits in `src/` (only, if anywhere, in this plan/spec docs). Remove or update any stragglers (docstrings, help text, README snippets in code comments).

- [ ] **Step 3: Manual smoke test with a tiny catalog**

Run (uses a 1–2 row CSV so it finishes fast; `--keep-raw` to inspect):
```bash
python -m cybersec_slm.cli run --sources sources/Sources.csv --workers 2 --limit 5 --keep-raw --source-timeout 120
```
Expected: log shows `ingest+clean: N sources … source_timeout=120s`, per-source `light-eda PASS`/clean lines interleaved, then `ingest+clean done: ok=… failed=… timed_out=…`, and `data/clean/` is populated. Confirm cleaning happened during (not only after) fetching by the interleaved log order.

- [ ] **Step 4: Commit any doc fixes**

```bash
git add -A
git commit -m "docs: align pipeline docstrings/help with overlapped ingest+clean"
```

---

## Self-Review

**Spec coverage:**
- Overlapped fetch + inline sequential clean → Task 2 (`run_ingest_clean`), models built once, ledger-after-clean, raw deletion.
- Reproducible dedup (disabled live + deterministic final pass) → Task 1 (`Deduper(enabled=False)`), Task 4 (`final_global_dedup` wired).
- Per-source timeout + hang doesn't stall + capped retries + bounded rebuild → Task 2 (logic) + Task 3 (tests).
- Fresh-run wipe of `data/clean`/`data/raw` → Task 2 (`_wipe_dir`).
- Bug fixes: O(n²) rescan → Task 1; partial-data cleaning (only `status=="ok"` cleaned) → Task 2; retry accounting/honest logs → Task 2; dead pre-`rmtree` scan removed with `run_aggregated_clean` → Task 4; unused worker params → Task 4.
- Wiring `run_v2_pipeline`, CLI `--source-timeout`, flows consistency → Tasks 4–5.
- Tests: overlap parity, timeout, resume, deterministic dedup, O(files) → Tasks 1–3, 6.

**Placeholder scan:** No TBD/TODO; every code step shows full code; every test step shows the assertions.

**Type consistency:** `clean_source_folder(folder, *, redactor, langf, translator, raw_root, clean_data_dir, flagged_dir, dropped_dir, limit)` is defined in Task 1 and called with `redactor/langf/translator/limit` in Task 2 (defaults cover the rest). `run_ingest_clean(...)` signature in Task 2 matches the call in Task 4's `run_v2_pipeline` and the CLI in Task 5. `_now`, `wait`, `POLL_INTERVAL_S`, `MAX_POOL_REBUILDS`, `MAX_SOURCE_RETRIES`, `_force_shutdown` all defined in Task 2 and exercised in Task 3.
