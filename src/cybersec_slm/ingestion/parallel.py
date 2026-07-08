#!/usr/bin/env python3
"""Parallel ingestion orchestrator — v2 four-phase pipeline.

Phase 1 — Parallel Ingest + Light EDA:
    Runs many sources concurrently across CPU cores.  Each worker fetches ONE
    source, converts to JSONL, and runs the light EDA quality gate.  Sources
    that fail the gate are moved to ``data/dropped/_rejected/`` with a sidecar
    report.  Sources that pass stay in ``data/raw/``.

Phase 2 — Aggregated Cleaning:
    After the pool drains, the full cleaning pipeline runs *sequentially* over
    the surviving ``data/raw/`` tree.  Dedup is enabled from the start (no
    separate cross-source pass needed) because we now see the full aggregate.

Phase 3 — Deep Global EDA:
    Runs the enhanced EDA with topic-balance analysis over ``data/clean/``.
    Returns a feedback report; blockers stop the pipeline.

Phase 4 — Schema Normalization:
    Maps cleaned records onto the canonical 22-field schema and appends them to
    ``data/final/dataset.jsonl``.

Legacy mode (``--legacy-streaming``) preserves the v1 fused fetch+clean
behavior for backward compatibility.

    cybersec-slm run --sources sources/Sources.csv --workers 4
    cybersec-slm all                          # full 4-phase pipeline
    cybersec-slm all --legacy-streaming       # v1 behavior
"""

from __future__ import annotations

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

# Append-only ledger of sources fully fetched+cleaned this build.  ``--resume``
# reads it to skip work that already succeeded (avoids re-downloading multi-GB
# sources and re-cleaning what is already in data/clean/).
COMPLETED_LEDGER = os.path.join(core.LOGS, "completed_sources.txt")

POLL_INTERVAL_S = 10.0             # wait() granularity for the consume loop
DEFAULT_SOURCE_TIMEOUT_S = 1800.0  # per-source wall-clock budget (30 min)
MAX_POOL_REBUILDS = 2              # bound pool restarts on timeout / broken pool
MAX_SOURCE_RETRIES = 1             # resubmit a transiently-failing source once


def _default_workers() -> int:
    return os.cpu_count() or 4


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


# ── Overlapped Ingest + Sequential Clean ──────────────────────────────────────

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
            remaining: set = set()

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
                            # Pool is dead: re-queue this descriptor (already
                            # discarded from `remaining`) plus the survivors,
                            # which the outer handler re-queues, then rebuild.
                            pending_descriptors.append(d)
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


# ── Phase 1: Parallel Ingest + Light EDA ──────────────────────────────────────

def run_parallel_ingest(spec: str | None = None, *,
                        workers: int | None = None,
                        resume: bool = False) -> dict:
    """Fetch all sources in parallel; each worker runs the light EDA gate.

    Returns a summary dict with ok/failed/skipped/rejected counts and the
    aggregated ingest rows + light-EDA reports.
    """
    os.environ["CYBERSEC_SLM_DATA_ROOT"] = core.DATA_ROOT

    descriptors = sources.load_descriptors(spec or sources.DEFAULT_CATALOG)
    if not descriptors:
        logger.warning("no sources to process")
        return {"ok": 0, "failed": 0, "skipped": 0, "rejected": 0,
                "ingest_rows": [], "light_eda_reports": [], "flags": []}

    if resume:
        done_keys = _load_completed(COMPLETED_LEDGER)
        n_before = len(descriptors)
        descriptors = [d for d in descriptors if descriptor_key(d) not in done_keys]
        n_skip = n_before - len(descriptors)
        if n_skip:
            logger.info(f"resume: skipping {n_skip} already-complete sources "
                        f"({len(descriptors)} left to process)")
        if not descriptors:
            logger.info("resume: all sources already fetched")
            return {"ok": 0, "failed": 0, "skipped": 0, "rejected": 0,
                    "ingest_rows": [], "light_eda_reports": [], "flags": [],
                    "all_done": True}
    else:
        _reset_completed(COMPLETED_LEDGER)
        cleaning_pipeline.reset_dedup_state()

    workers = workers or _default_workers()
    logger.info(f"phase 1: ingesting {len(descriptors)} sources with {workers} workers "
                f"-> {core.RAW_DATA}")

    log = IngestLog()
    ingest_rows: list[dict] = []
    light_eda_reports: list[dict] = []
    source_flags: list[dict] = []
    ok = failed = skipped = rejected = 0
    ctx = mp.get_context("spawn")
    os.makedirs(core.LOGS, exist_ok=True)
    ledger = open(COMPLETED_LEDGER, "a", encoding="utf-8")

    max_attempts = 3
    try:
        for attempt in range(1, max_attempts + 1):
            if not descriptors:
                break
                
            if attempt > 1:
                logger.info(f"phase 1 (attempt {attempt}/{max_attempts}): retrying {len(descriptors)} "
                            "failed sources with troubleshooting...")

            next_descriptors = []
            try:
                with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as ex:
                    futs = {ex.submit(worker.process_source, d, data_root=core.DATA_ROOT): d
                            for d in descriptors}
                    for fut in as_completed(futs):
                        d = futs[fut]
                        label = d.get("ref") or d.get("slug") or d.get("kind")
                        try:
                            meta = fut.result()
                        except Exception as ex2:
                            logger.error(f"  worker crashed for {label}: "
                                         f"{type(ex2).__name__}: {ex2}")
                            next_descriptors.append(d)
                            if attempt == max_attempts:
                                failed += 1
                            continue

                        status = meta.get("status")
                        if status not in ("ok", "skipped", "rejected"):
                            next_descriptors.append(d)
                            if attempt == max_attempts:
                                failed += 1
                                ingest_rows.extend(meta.get("ingest_rows", []))
                        else:
                            ingest_rows.extend(meta.get("ingest_rows", []))
                            leda = meta.get("light_eda_report", {})
                            if leda:
                                light_eda_reports.append(leda)
                            flags = meta.get("flags", {})
                            if flags:
                                source_flags.append({"source": label, **flags})

                            if status == "ok":
                                ok += 1
                            elif status == "skipped":
                                skipped += 1
                            elif status == "rejected":
                                rejected += 1
                            
                            if status in ("ok", "skipped"):
                                ledger.write(descriptor_key(d) + "\n")
                                ledger.flush()
            except BrokenProcessPool as ex2:
                logger.error(f"process pool broke: {ex2}")
                next_descriptors = descriptors
                if attempt == max_attempts:
                    failed += len(descriptors)
            
            descriptors = next_descriptors
    finally:
        ledger.close()

    logger.info(f"phase 1 done: ok={ok} failed={failed} skipped={skipped} "
                f"rejected={rejected}")
    log.record_many(ingest_rows)
    ingestion_run.show_table()

    return {"ok": ok, "failed": failed, "skipped": skipped, "rejected": rejected,
            "ingest_rows": ingest_rows, "light_eda_reports": light_eda_reports,
            "flags": source_flags}


# ── Phase 2: Aggregated Cleaning ──────────────────────────────────────────────

def run_aggregated_clean(*, keep_raw: bool = False, limit: int | None = None) -> dict:
    """Run the full cleaning pipeline over data/raw/ -> data/clean/.

    This is a single sequential pass with global dedup enabled from the start
    (no separate cross-source pass needed).
    """
    from ..cleaning.dedup import Deduper
    from ..cleaning.langfilter import LangFilter
    from ..cleaning.pii import Redactor
    from ..cleaning.translate import Translator

    logger.info(f"phase 2: aggregated cleaning {core.RAW_DATA} -> {core.CLEAN_DATA}")

    files = list(cleaning_pipeline.find_input_files(core.RAW_DATA))
    if not files:
        logger.warning("phase 2: no raw data to clean")
        return {"files": 0, "in": 0, "out": 0}

    # Full dedup enabled from the start — we see the whole corpus.
    deduper = Deduper(enabled=True)
    redactor = cleaning_pipeline._cleaner(Redactor)
    langf = cleaning_pipeline._cleaner(LangFilter)
    translator = cleaning_pipeline._cleaner(Translator)

    rows = cleaning_pipeline.clean_files(
        files, deduper=deduper, redactor=redactor, langf=langf,
        translator=translator,
        out_cleaned=core.CLEAN_DATA,
        out_flagged=core.FLAGGED,
        out_dropped=core.DROPPED,
        limit=limit,
    )

    if rows:
        cleaning_pipeline._write_report(rows)

    total_in = sum(r.get("in", 0) for r in rows)
    total_out = sum(r.get("out", 0) for r in rows)
    logger.info(f"phase 2 done: {len(rows)} files, in={total_in} out={total_out}")

    # Clean up raw data unless --keep-raw
    if not keep_raw:
        import shutil
        for ap, _sub, _source, _rel in cleaning_pipeline.find_input_files(core.RAW_DATA):
            pass  # just iterate to confirm; we remove the whole tree
        try:
            shutil.rmtree(core.RAW_DATA, ignore_errors=True)
            logger.info("phase 2: deleted data/raw/ (use --keep-raw to retain)")
        except OSError:
            pass

    return {"files": len(rows), "in": total_in, "out": total_out}


# ── Phase 3: Deep Global EDA ─────────────────────────────────────────────────

def run_deep_eda(*, enforce: bool = True) -> dict:
    """Run the enhanced EDA with topic-balance analysis over data/clean/."""
    from ..eda import run_eda
    logger.info("phase 3: deep global EDA")
    return run_eda(enforce=enforce)


# ── Phase 4: Schema Normalization ─────────────────────────────────────────────

def run_normalize(*, resume: bool = True) -> dict:
    """Map cleaned records onto the canonical schema and append to final dataset."""
    from ..normalize import run_normalization
    logger.info("phase 4: schema normalization -> data/final/dataset.jsonl")
    return run_normalization(resume=resume)


# ── Combined Four-Phase Pipeline ──────────────────────────────────────────────

def run_v2_pipeline(spec: str | None = None, *,
                    workers: int | None = None,
                    resume: bool = False,
                    keep_raw: bool = False,
                    limit: int | None = None,
                    enforce_eda: bool = True,
                    normalize: bool = True) -> dict:
    """Run the full v2 four-phase pipeline: ingest -> clean -> EDA -> normalize.

    Parameters
    ----------
    spec : str | None
        Path to sources CSV; uses default catalog when omitted.
    workers : int | None
        Process pool size; defaults to min(cpu, 8).
    resume : bool
        Skip sources already fetched in a prior run.
    keep_raw : bool
        Keep data/raw/ after cleaning.
    limit : int | None
        Cap records per file (for smoke tests).
    enforce_eda : bool
        Raise SufficiencyError on EDA blockers (default True).
    normalize : bool
        Run phase 4 (normalization); False stops after EDA.
    """
    from ..eda import SufficiencyError

    # Phase 1: Parallel Ingest + Light EDA
    ingest_result = run_parallel_ingest(spec, workers=workers, resume=resume)

    # Phase 2: Aggregated Cleaning (sequential over the full raw pool)
    clean_result = run_aggregated_clean(keep_raw=keep_raw, limit=limit)

    # Phase 3: Deep Global EDA
    try:
        eda_result = run_deep_eda(enforce=enforce_eda)
    except SufficiencyError as exc:
        logger.error(str(exc))
        print("Pipeline halted at the EDA sufficiency gate — "
              "address the blockers above and re-run.")
        return {"phase": "eda", "error": str(exc), "ingest": ingest_result,
                "clean": clean_result}

    # Phase 4: Schema Normalization (append to final)
    norm_result = {}
    if normalize:
        # Fresh build: ingestion regenerates data/clean/ upstream, so normalize
        # fresh (resume=False) instead of appending/deduping against a stale dataset.
        norm_result = run_normalize(resume=resume)

    return {"phase": "complete", "ingest": ingest_result, "clean": clean_result,
            "eda": eda_result, "normalize": norm_result}



