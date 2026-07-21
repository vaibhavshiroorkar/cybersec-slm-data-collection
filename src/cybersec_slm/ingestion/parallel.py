#!/usr/bin/env python3
"""Parallel ingestion orchestrator - the corpus-build stages of the pipeline.

Implements stages 2-5 of the canonical pipeline (sourcing, stage 1, is a separate
curation step in ``sourcing/``). ``run_v2_pipeline`` runs these four physically
separate stages in order (no ingest/clean overlap):

Stage 2 - Ingest (``run_ingest``):
    A spawn ``ProcessPoolExecutor`` of fetch-only workers fetches every source to
    ``data/raw/``, converting to JSONL and running the light-EDA gate (rejected
    sources move to ``data/dropped/_rejected/``). A per-source wall-clock timeout
    abandons a hung source so it cannot stall the run. Raw is left in place.

Stage 3 - Clean (``run_clean``):
    The whole ``data/raw/`` tree is cleaned into ``data/clean/`` (per-source
    transforms, per-source dedup disabled), then one deterministic cross-source
    dedup pass (``final_global_dedup``) runs. ``data/raw/`` is retained by default
    (pass ``keep_raw=False`` to delete it).

Then (``run_v2_pipeline``):
    * deep global EDA with topic-balance analysis (blockers stop the pipeline)
    * schema normalization -> ``data/final/dataset.jsonl``

    cybersec-slm ingest --sources sources/Sources.csv --workers 4
    cybersec-slm clean
    cybersec-slm all                          # corpus build: ingest..schema

The shared process-pool machinery lives in ``_run_pool``; ``run_ingest`` drives it.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import shutil
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, as_completed, wait
from concurrent.futures.process import BrokenProcessPool

from .. import core
from ..cleaning import pipeline as cleaning_pipeline
from . import run as ingestion_run
from . import sources, worker
from .common import IngestLog, logger
from .sources import descriptor_key

# Append-only ledger of sources fully fetched+cleaned this build.  ``--resume``
# reads it to skip work that already succeeded (avoids re-downloading multi-GB
# sources and re-cleaning what is already in data/clean/).
COMPLETED_LEDGER = os.path.join(core.LOGS, "completed_sources.txt")
# Per-source clean progress for the separate clean stage. ``run_clean`` can
# resume a prior run by skipping already-cleaned raw source folders.
CLEANED_LEDGER = os.path.join(core.LOGS, "cleaned_sources.txt")

POLL_INTERVAL_S = 5.0              # wait() granularity for the consume loop
DEFAULT_SOURCE_TIMEOUT_S = 1800.0  # per-source wall-clock budget (30 min)
MAX_POOL_REBUILDS = 5              # allow several pool restarts on timeout / broken pool
MAX_SOURCE_RETRIES = 2             # resubmit transiently-failing sources twice
RETRY_DELAY_S = 5.0                # wait 5 seconds before resubmitting to pool
# Error signatures that are deterministic, not transient: retrying just wastes
# time (and, for pyo3 panics, re-crashes workers). Fail them on the first attempt.
_NON_RETRYABLE_MARKERS = (
    "401 Unauthorized", "403 Forbidden", "Unauthorized",
    "PanicException", "pyo3_runtime", "PicklingError",
)


def _default_workers() -> int:
    """Concurrent sources in the ingest pool.

    Previously hard-capped at 8 regardless of machine size, which throttled
    throughput on anything bigger than an 8-core box for no real reason: each
    worker spends nearly all its time blocked on network I/O (an HTTP fetch or
    a Scrapy subprocess), not CPU, so running well past the core count is
    normal and safe. The ceiling here just guards against an unconsidered
    default hammering a lot of third-party hosts at once on a very large
    machine; raise or lower it with $CYBERSEC_SLM_MAX_WORKERS, or pass
    --workers explicitly to override this function entirely.
    """
    cpu = os.cpu_count() or 4
    ceiling = int(os.environ.get("CYBERSEC_SLM_MAX_WORKERS", 32))
    return max(2, min(ceiling, cpu * 2))


def _now() -> float:
    """Monotonic clock indirection (a test seam for the timeout sweep)."""
    return time.monotonic()


def _wipe_dir(path: str) -> None:
    """Remove a data tree so a fresh (non-resume) build starts clean."""
    shutil.rmtree(path, ignore_errors=True)


def _empty_summary() -> dict:
    return {"ok": 0, "failed": 0, "skipped": 0, "rejected": 0, "timed_out": 0,
            "ingest_rows": [], "light_eda_reports": [], "flags": [],
            "clean_rows": [], "failed_keys": []}


def _load_completed(path: str) -> set[str]:
    if not os.path.exists(path):
        return set()
    try:
        with open(path, encoding="utf-8") as f:
            return {ln.strip() for ln in f if ln.strip()}
    except OSError:
        return set()


def _reset_completed(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def _load_cleaned(path: str) -> set[str]:
    if not os.path.exists(path):
        return set()
    try:
        with open(path, encoding="utf-8") as f:
            return {ln.strip() for ln in f if ln.strip()}
    except OSError:
        return set()


def _reset_cleaned(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def _source_dirs(raw_root: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if not os.path.isdir(raw_root):
        return out
    for dom in os.scandir(raw_root):
        if not dom.is_dir():
            continue
        for src in os.scandir(dom.path):
            if src.is_dir():
                out.append((src.path, f"{dom.name}/{src.name}"))
    return out


def _force_shutdown(pool) -> None:
    """Shut a pool down without waiting, terminating any leaked/hung workers."""
    for p in list(getattr(pool, "_processes", {}).values() or []):
        try:
            p.terminate()
        except Exception:
            pass
    try:
        pool.shutdown(wait=False, cancel_futures=True)
    except Exception:
        pass


def _clean_source(src_dir: str, sid: str, raw_root: str,
                  limit: int | None, drop_non_english: bool) -> tuple[str, list[dict]]:
    rows = cleaning_pipeline.clean_one_source(
        src_dir, raw_root=raw_root,
        clean_data_dir=cleaning_pipeline.OUT_CLEAN_DATA,
        limit=limit, drop_non_english=drop_non_english)
    return sid, rows


def _clean_chunk(chunk: tuple, sid: str, limit: int | None,
                 drop_non_english: bool, out_dirs: tuple[str, str, str]
                 ) -> tuple[str, list[dict]]:
    clean_dir, flagged_dir, dropped_dir = out_dirs
    rows = cleaning_pipeline.clean_chunk(
        chunk, clean_data_dir=clean_dir, flagged_dir=flagged_dir,
        dropped_dir=dropped_dir, limit=limit, drop_non_english=drop_non_english)
    return sid, rows


def _clean_work(to_clean: list[tuple[str, str]], raw_root: str) -> list[tuple]:
    by_source: list[tuple[int, str, list]] = []
    for src_dir, sid in to_clean:
        if not os.path.isdir(src_dir):
            logger.warning(f"clean: no raw data for source {sid}")
            continue
        files = cleaning_pipeline._source_files(src_dir, raw_root)
        size = 0
        for ap, _sub, _src, _rel in files:
            try:
                size += os.path.getsize(ap)
            except OSError:
                pass
        by_source.append((size, sid, cleaning_pipeline.shard_files(files)))
    by_source.sort(key=lambda t: t[0])
    return [(sid, chunk) for _size, sid, chunks in by_source for chunk in chunks]


def _label(d) -> str:
    return d.get("ref") or d.get("slug") or d.get("kind")


def _run_pool(descriptors, *, submit, on_result, workers: int,
              source_timeout: float, summary: dict, ctx=None) -> dict:
    ctx = ctx or mp.get_context("spawn")
    retries: dict[str, int] = {}
    pending_descriptors = list(descriptors)
    rebuilds = 0

    while pending_descriptors and rebuilds <= MAX_POOL_REBUILDS:
        round_descriptors = pending_descriptors
        pending_descriptors = []
        pool = ProcessPoolExecutor(max_workers=workers, mp_context=ctx)
        started: dict = {}
        fut_desc: dict = {}
        remaining: set = set()
        delayed_retries: list[tuple[float, dict]] = []

        def _submit(d, pool=pool, started=started, fut_desc=fut_desc,
                    remaining=remaining):
            fut = submit(pool, d)
            started[fut] = _now()
            fut_desc[fut] = d
            remaining.add(fut)

        pending_iter = iter(round_descriptors)
        for _ in range(workers):
            try:
                _submit(next(pending_iter))
            except StopIteration:
                break

        def _fail_or_retry(d, error_text: str = ""):
            k = descriptor_key(d)
            # Deterministic failures (auth, Rust panics, pickling) don't recover
            # on retry — skip the retry queue and record them as failed now.
            if error_text and any(m in error_text for m in _NON_RETRYABLE_MARKERS):
                logger.warning(f"  not retrying {_label(d)}: non-transient failure")
                summary["failed"] += 1
                summary.setdefault("failed_keys", []).append(k)
                return
            if retries.get(k, 0) < MAX_SOURCE_RETRIES:
                retries[k] = retries.get(k, 0) + 1
                # Delay the retry to avoid instantly slamming a rate-limited server
                delayed_retries.append((_now() + RETRY_DELAY_S, d))
            else:
                summary["failed"] += 1
                summary.setdefault("failed_keys", []).append(k)

        broke = timed_out = False
        try:
            while remaining or delayed_retries:
                # Process any retries that have waited out their delay period
                now = _now()
                ready_to_retry = [item for item in delayed_retries if item[0] <= now]
                for item in ready_to_retry:
                    delayed_retries.remove(item)
                    _submit(item[1])

                # If we have delayed retries but no active futures, sleep briefly
                if not remaining:
                    time.sleep(0.5)
                    continue

                done, _pend = wait(remaining, timeout=POLL_INTERVAL_S,
                                   return_when=FIRST_COMPLETED)
                
                for fut in done:
                    remaining.discard(fut)
                    d = fut_desc[fut]
                    try:
                        meta = fut.result()
                    except BrokenProcessPool as ex:
                        # A worker hard-crashed (e.g. a Rust/pyo3 panic in polars).
                        # That source is a deterministic failure — don't requeue
                        # it (it will just crash the rebuilt pool again). The
                        # other in-flight futures are salvaged by the except
                        # block below.
                        logger.error(f"  pool broke on {_label(d)}: "
                                     f"{type(ex).__name__}: {ex}")
                        summary["failed"] += 1
                        summary.setdefault("failed_keys", []).append(
                            descriptor_key(d))
                        raise
                    except Exception as ex:
                        logger.error(f"  worker crashed for {_label(d)}: "
                                     f"{type(ex).__name__}: {ex}")
                        _fail_or_retry(d, error_text=f"{type(ex).__name__}: {ex}")
                        continue
                    if not on_result(d, meta):
                        logger.warning(f"  FAILED {_label(d)}: "
                                       f"{meta.get('error')}")
                        _fail_or_retry(d, error_text=str(meta.get("error") or ""))
                        continue
                    try:
                        _submit(next(pending_iter))
                    except StopIteration:
                        pass
                
                now = _now()
                overdue = [f for f in remaining
                           if now - started[f] > source_timeout]
                if overdue:
                    for f in overdue:
                        logger.error(f"  TIMEOUT {_label(fut_desc[f])}: exceeded "
                                     f"{source_timeout:.0f}s; abandoning")
                        summary["timed_out"] += 1
                        summary["failed"] += 1
                        summary.setdefault("failed_keys", []).append(
                            descriptor_key(fut_desc[f]))
                        remaining.discard(f)
                    # Requeue only the still-running (non-overdue) futures so
                    # their work is not lost when we rebuild the pool below.
                    # Timed-out ones are NOT requeued: they just counted as failed.
                    pending_descriptors.extend(fut_desc[f] for f in list(remaining))
                    remaining.clear()
                    timed_out = True
                    break
        except BrokenProcessPool as ex:
            logger.error(f"process pool broke: {ex}")
            pending_descriptors.extend(fut_desc[f] for f in remaining)
            broke = True
        finally:
            _force_shutdown(pool)
            pending_descriptors.extend(pending_iter)
            # Salvage delayed retries back into the pending queue for the next pool rebuild
            pending_descriptors.extend([item[1] for item in delayed_retries])

        if timed_out or broke:
            rebuilds += 1
            if rebuilds > MAX_POOL_REBUILDS and pending_descriptors:
                logger.error(f"  giving up on {len(pending_descriptors)} sources "
                             f"after {MAX_POOL_REBUILDS} pool rebuilds")
                summary["failed"] += len(pending_descriptors)
                summary.setdefault("failed_keys", []).extend(
                    descriptor_key(d) for d in pending_descriptors)
                pending_descriptors = []
    return summary


# ── Stage 2: Ingest (fetch-only) ──────────────────────────────────────────────

def run_ingest(spec: str | None = None, *, workers: int | None = None,
               resume: bool = False, retry_failed: bool = False, limit: int | None = None,
               source_timeout: float = DEFAULT_SOURCE_TIMEOUT_S,
               max_source_gb: float | None = None, crawl: bool = True,
               domains: list[str] | None = None,
               sources_only: list[str] | None = None,
               scan_hazards: bool = True) -> dict:
    
    os.environ["CYBERSEC_SLM_DATA_ROOT"] = core.DATA_ROOT
    max_mb = max_source_gb * 1024 if max_source_gb else None
    descriptors = sources.load_descriptors(spec or sources.DEFAULT_CATALOG,
                                           max_mb=max_mb)
    if not descriptors:
        logger.warning("no sources to ingest")
        return _empty_summary()

    selected = list(domains) if domains else None
    if selected:
        wanted = set(selected)
        n_before = len(descriptors)
        descriptors = [d for d in descriptors if d.get("domain") in wanted]
        logger.info(f"ingest: selective - {len(descriptors)} of {n_before} sources "
                    f"in {sorted(wanted)}")
        if not descriptors:
            logger.warning(f"ingest: no sources match sub-domain(s) {sorted(wanted)}")
            return _empty_summary()

    picked_sources = set(sources_only) if sources_only else None
    if picked_sources:
        n_before = len(descriptors)
        descriptors = [d for d in descriptors
                       if descriptor_key(d) in picked_sources]
        logger.info(f"ingest: row-level - {len(descriptors)} of {n_before} sources "
                    f"match {len(picked_sources)} selected row(s)")
        if not descriptors:
            logger.warning("ingest: no sources match the selected rows")
            return _empty_summary()

    if resume:
        done_keys = _load_completed(COMPLETED_LEDGER)
        
        if retry_failed:
            import sqlite3
            db_path = os.path.join(core.LOGS, "ingest_log.sqlite")
            true_completed = set()
            if os.path.exists(db_path):
                try:
                    with sqlite3.connect(db_path) as con:
                        cur = con.cursor()
                        cur.execute("SELECT domain, name FROM ingest WHERE status IN ('ok', 'skipped', 'rejected')")
                        true_completed = {f"{row[0]}/{row[1]}" for row in cur.fetchall()}
                except Exception as ex:
                    logger.warning(f"ingest: failed to read ingest_log.sqlite for --retry-failed: {ex}")
            
            retrying_keys = done_keys - true_completed
            if retrying_keys:
                done_keys = done_keys - retrying_keys
                try:
                    with open(COMPLETED_LEDGER, "w", encoding="utf-8") as f:
                        for k in sorted(done_keys):
                            f.write(k + "\n")
                    logger.info(f"ingest: --retry-failed removed {len(retrying_keys)} failed sources from ledger")
                except OSError as ex:
                    logger.warning(f"ingest: failed to update ledger for --retry-failed: {ex}")

        n_before = len(descriptors)
        descriptors = [d for d in descriptors if descriptor_key(d) not in done_keys]
        n_skip = n_before - len(descriptors)
        if n_skip:
            logger.info(f"ingest: resume skipping {n_skip} already-fetched sources "
                        f"({len(descriptors)} left)")
        if not descriptors:
            logger.info("ingest: resume - all sources already fetched")
            return {**_empty_summary(), "all_done": True}
    elif picked_sources:
        pass
    elif selected:
        for dom in selected:
            _wipe_dir(os.path.join(core.RAW_DATA, dom))
    else:
        _reset_completed(COMPLETED_LEDGER)
        _wipe_dir(core.RAW_DATA)

    workers = workers or _default_workers()
    logger.info(f"ingest: {len(descriptors)} sources, {workers} workers, "
                f"source_timeout={source_timeout:.0f}s -> {core.RAW_DATA}")

    ctx = mp.get_context("spawn")
    os.makedirs(core.LOGS, exist_ok=True)
    ledger = open(COMPLETED_LEDGER, "a", encoding="utf-8")
    log = IngestLog()
    summary = _empty_summary()

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
            summary["ok"] += 1
            ledger.write(descriptor_key(d) + "\n"); ledger.flush()
        elif status == "skipped":
            summary["skipped"] += 1
            ledger.write(descriptor_key(d) + "\n"); ledger.flush()
        elif status == "rejected":
            summary["rejected"] += 1
            ledger.write(descriptor_key(d) + "\n"); ledger.flush()
        else:
            return False 
        return True

    def _submit(pool, d):
        return pool.submit(worker.process_source, d, data_root=core.DATA_ROOT,
                           limit=limit, clean=False, crawl=crawl,
                           scan_hazards=scan_hazards)

    try:
        _run_pool(descriptors, submit=_submit, on_result=_record, workers=workers,
                  source_timeout=source_timeout, summary=summary, ctx=ctx)
        for k in summary.get("failed_keys", []):
            ledger.write(k + "\n")
        ledger.flush()
    finally:
        ledger.close()

    log.record_many(summary["ingest_rows"])
    ingestion_run.show_table()
    logger.info(f"ingest: done ok={summary['ok']} failed={summary['failed']} "
                f"skipped={summary['skipped']} rejected={summary['rejected']} "
                f"timed_out={summary['timed_out']}")
    return summary


# ── Stage 3: Clean (whole tree + cross-source dedup) ──────────────────────────

def _split_source_id(sid: str) -> tuple[str, str] | None:
    dom, _, src = str(sid).replace("\\", "/").partition("/")
    dom, src = dom.strip("/ "), src.strip("/ ")
    return (dom, src) if dom and src else None


def run_clean(*, keep_raw: bool = True, limit: int | None = None,
              resume: bool = False, drop_non_english: bool = False,
              domains: list[str] | None = None,
              sources_only: list[str] | None = None,
              workers: int | None = None) -> dict:
    
    raw_root = core.RAW_DATA
    selected = list(domains) if domains else None
    picked = [p for p in (_split_source_id(s) for s in (sources_only or [])) if p]
    if resume:
        cleaned_sources = _load_cleaned(CLEANED_LEDGER)
        if cleaned_sources:
            logger.info(f"clean: resume skipping {len(cleaned_sources)} already-cleaned source(s)")
    else:
        cleaning_pipeline.reset_dedup_state()
        _reset_cleaned(CLEANED_LEDGER)
        cleaned_sources = set()
        if picked:
            for dom, src in picked:
                _wipe_dir(os.path.join(cleaning_pipeline.OUT_CLEAN_DATA, dom, src))
        elif selected:
            for dom in selected:
                _wipe_dir(os.path.join(cleaning_pipeline.OUT_CLEAN_DATA, dom))
        else:
            _wipe_dir(cleaning_pipeline.OUT_CLEAN_DATA)
            try:
                os.remove(os.path.join(cleaning_pipeline.REPORTS, "clean_report.csv"))
            except OSError:
                pass

    if not os.path.isdir(raw_root):
        logger.warning("clean: no raw data to clean (run `cybersec-slm ingest` first)")
        return {"files": 0, "in": 0, "out": 0, "dedup": {}}

    if picked:
        sources = []
        for dom, src in picked:
            src_dir = os.path.join(raw_root, dom, src)
            sources.append((src_dir, f"{dom}/{src}"))
    elif selected:
        sources = []
        for dom in selected:
            dom_dir = os.path.join(raw_root, dom)
            if os.path.isdir(dom_dir):
                for src in os.scandir(dom_dir):
                    if src.is_dir():
                        sources.append((src.path, f"{dom}/{src.name}"))
            else:
                logger.warning(f"clean: no raw data for sub-domain {dom!r}")
    else:
        sources = _source_dirs(raw_root)

    to_clean = [(src_dir, sid) for src_dir, sid in sources
                if sid not in cleaned_sources]
    if resume and not to_clean and sources:
        logger.info("clean: resume - all selected sources already cleaned")

    os.makedirs(core.LOGS, exist_ok=True)
    ledger = open(CLEANED_LEDGER, "a", encoding="utf-8")
    rows: list[dict] = []
    if workers is None or workers <= 1:
        for src_dir, sid in to_clean:
            if not os.path.isdir(src_dir):
                logger.warning(f"clean: no raw data for source {sid}")
                continue
            logger.info(f"clean: {sid} -> {cleaning_pipeline.OUT_CLEAN_DATA}")
            src_rows = cleaning_pipeline.clean_one_source(
                src_dir, raw_root=raw_root,
                clean_data_dir=cleaning_pipeline.OUT_CLEAN_DATA, limit=limit,
                drop_non_english=drop_non_english)
            rows += src_rows
            ledger.write(sid + "\n")
            ledger.flush()
    else:
        work = _clean_work(to_clean, raw_root)
        outstanding: dict[str, int] = {}
        for sid, _chunk in work:
            outstanding[sid] = outstanding.get(sid, 0) + 1
        sharded = len(work) - len(outstanding)
        workers = max(1, min(workers, len(work)))
        logger.info(f"clean: parallelizing over {workers} workers "
                    f"({len(work)} window(s) across {len(outstanding)} source(s)"
                    + (f", {sharded} extra from sharding big files)" if sharded
                       else ")"))
        out_dirs = (cleaning_pipeline.OUT_CLEAN_DATA, cleaning_pipeline.OUT_FLAGGED,
                    cleaning_pipeline.OUT_DROPPED)
        ctx = mp.get_context("spawn")
        with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as pool:
            futures = {
                pool.submit(_clean_chunk, chunk, sid, limit, drop_non_english,
                            out_dirs): sid
                for sid, chunk in work
            }
            for fut in as_completed(futures):
                sid = futures[fut]
                try:
                    _, src_rows = fut.result()
                except Exception as ex:
                    logger.error(f"clean: worker failed for {sid}: {type(ex).__name__}: {ex}")
                    ledger.close()
                    raise
                rows.extend(src_rows)
                outstanding[sid] -= 1
                if outstanding[sid] == 0:         
                    ledger.write(sid + "\n")
                    ledger.flush()
    ledger.close()

    if rows:
        cleaning_pipeline._write_report(cleaning_pipeline.merge_report_rows(rows))

    dedup = cleaning_pipeline.final_global_dedup(
        cleaning_pipeline.OUT_CLEAN_DATA, resume=resume)

    if not keep_raw:
        if picked:
            for dom, src in picked:
                _wipe_dir(os.path.join(raw_root, dom, src))
        elif selected:
            for dom in selected:
                _wipe_dir(os.path.join(raw_root, dom))
        else:
            _wipe_dir(raw_root)

    total_in = sum(r.get("in", 0) for r in rows)
    total_out = sum(r.get("out", 0) for r in rows)
    logger.info(f"clean: done files={len(rows)} in={total_in} out={total_out} "
                f"exact_dups={dedup.get('exact_dups')} kept={dedup.get('kept')}")
    return {"files": len(rows), "in": total_in, "out": total_out, "dedup": dedup}


# ── Sequential clean of an already-fetched raw tree ───────────────────────────

def clean_raw_tree(*, keep_raw: bool = False, limit: int | None = None) -> dict:
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
    logger.info(f"clean_raw_tree: {len(rows)} files, in={total_in} out={total_out}")
    return {"files": len(rows), "in": total_in, "out": total_out}


# ── Phase 3: Deep Global EDA ─────────────────────────────────────────────────

def run_deep_eda(*, enforce: bool = True) -> dict:
    from ..eda import run_eda
    logger.info("phase 3: deep global EDA")
    return run_eda(enforce=enforce)


# ── Phase 4: Schema Normalization ─────────────────────────────────────────────

def run_normalize(*, resume: bool = True) -> dict:
    from ..normalize import run_normalization
    logger.info("phase 4: schema normalization -> data/final/dataset.jsonl")
    return run_normalization(resume=resume)


# ── Combined Pipeline ─────────────────────────────────────────────────────────

def run_v2_pipeline(spec: str | None = None, *,
                    workers: int | None = None,
                    resume: bool = False,
                    retry_failed: bool = False,
                    keep_raw: bool = True,
                    limit: int | None = None,
                    source_timeout: float = DEFAULT_SOURCE_TIMEOUT_S,
                    max_source_gb: float | None = None,
                    drop_non_english: bool = False,
                    crawl: bool = True,
                    scan_hazards: bool = True,
                    enforce_eda: bool = True,
                    normalize: bool = True,
                    clean_workers: int | None = None) -> dict:
    
    from ..eda import SufficiencyError

    ingest_result = run_ingest(spec, workers=workers, resume=resume, retry_failed=retry_failed, limit=limit,
                               source_timeout=source_timeout,
                               max_source_gb=max_source_gb, crawl=crawl,
                               scan_hazards=scan_hazards)

    clean_result = run_clean(keep_raw=keep_raw, limit=limit, resume=resume,
                             drop_non_english=drop_non_english,
                             workers=clean_workers)

    try:
        eda_result = run_deep_eda(enforce=enforce_eda)
    except SufficiencyError as exc:
        logger.error(str(exc))
        print("Pipeline halted at the EDA sufficiency gate - "
              "address the blockers above and re-run.")
        return {"phase": "eda", "error": str(exc), "ingest": ingest_result,
                "clean": clean_result}

    norm_result = {}
    if normalize:
        norm_result = run_normalize(resume=resume)

    return {"phase": "complete", "ingest": ingest_result, "clean": clean_result,
            "eda": eda_result, "normalize": norm_result}