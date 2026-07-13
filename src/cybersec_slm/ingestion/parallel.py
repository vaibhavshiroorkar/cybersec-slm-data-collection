#!/usr/bin/env python3
"""Parallel ingestion orchestrator - the five-stage pipeline.

The pipeline runs five physically separate stages (no ingest/clean overlap):

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
    cybersec-slm all                          # full pipeline (all five stages)

The shared process-pool machinery lives in ``_run_pool``; ``run_ingest`` drives it.
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

POLL_INTERVAL_S = 5.0              # wait() granularity for the consume loop
DEFAULT_SOURCE_TIMEOUT_S = 1800.0  # per-source wall-clock budget (30 min)
MAX_POOL_REBUILDS = 5              # allow several pool restarts on timeout / broken pool
MAX_SOURCE_RETRIES = 2             # resubmit transiently-failing sources twice


def _default_workers() -> int:
    return max(2, min(8, os.cpu_count() or 4))


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
    for p in list(getattr(pool, "_processes", {}).values() or []):
        try:
            p.terminate()
        except Exception:
            pass
    try:
        pool.shutdown(wait=False, cancel_futures=True)
    except Exception:
        pass


def _label(d) -> str:
    return d.get("ref") or d.get("slug") or d.get("kind")


def _run_pool(descriptors, *, submit, on_result, workers: int,
              source_timeout: float, summary: dict, ctx=None) -> dict:
    """Drive a ProcessPoolExecutor over `descriptors`, generically.

    This owns every hard part of the parallel run and knows nothing about fetch
    vs clean:

    * ``submit(pool, descriptor) -> Future`` submits one descriptor's work.
    * ``on_result(descriptor, meta) -> bool`` records a finished result; it must
      return ``False`` for an unknown/failed result so the runner retries it.

    The runner keeps ``workers`` submissions in flight, consumes with
    ``wait(FIRST_COMPLETED)``, sweeps per-source timeouts, handles a
    ``BrokenProcessPool`` by re-queueing survivors and rebuilding (up to
    ``MAX_POOL_REBUILDS``), retries transiently-failing sources up to
    ``MAX_SOURCE_RETRIES``, and drains any descriptors left unconsumed when a round
    ends early. It mutates ``summary["failed"]`` and ``summary["timed_out"]``.
    """
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
                    if not on_result(d, meta):
                        logger.warning(f"  FAILED {_label(d)}: "
                                       f"{meta.get('error')}")
                        _fail_or_retry(d)
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
            # A round that ends early (timeout/broke) leaves descriptors still
            # sitting unconsumed in this round's local iterator - only in-flight
            # futures got re-queued above. Drain the rest back into
            # pending_descriptors so they aren't silently dropped from the run.
            pending_descriptors.extend(pending_iter)

        if timed_out or broke:
            rebuilds += 1
            if rebuilds > MAX_POOL_REBUILDS and pending_descriptors:
                logger.error(f"  giving up on {len(pending_descriptors)} sources "
                             f"after {MAX_POOL_REBUILDS} pool rebuilds")
                summary["failed"] += len(pending_descriptors)
                pending_descriptors = []
    return summary


# ── Stage 2: Ingest (fetch-only) ──────────────────────────────────────────────

def run_ingest(spec: str | None = None, *, workers: int | None = None,
               resume: bool = False, limit: int | None = None,
               source_timeout: float = DEFAULT_SOURCE_TIMEOUT_S,
               max_source_gb: float | None = None, crawl: bool = True,
               domains: list[str] | None = None) -> dict:
    """Fetch every source to ``data/raw/`` (the ingest stage); no cleaning.

    Each source is fetched and passed through the license + light-EDA gate by a
    fetch-only worker (``process_source(clean=False)``); its raw folder is left in
    place for the separate clean stage. Fresh (non-resume) wipes ``data/raw/`` and
    the resume ledger first; ``resume`` skips sources already fetched. With
    ``crawl=False`` website (crawl) sources are recorded as skipped, not fetched.

    ``domains`` restricts the run to those Sub-Domains (a *selective* ingest):
    only their sources are fetched, and a fresh run wipes only those Sub-Domains'
    ``data/raw/<domain>/`` folders (leaving every other Sub-Domain and the resume
    ledger untouched). Cleaning, cross-source dedup, and raw deletion all belong to
    :func:`run_clean`.
    """
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

    if resume:
        done_keys = _load_completed(COMPLETED_LEDGER)
        n_before = len(descriptors)
        descriptors = [d for d in descriptors if descriptor_key(d) not in done_keys]
        n_skip = n_before - len(descriptors)
        if n_skip:
            logger.info(f"ingest: resume skipping {n_skip} already-fetched sources "
                        f"({len(descriptors)} left)")
        if not descriptors:
            logger.info("ingest: resume - all sources already fetched")
            return {**_empty_summary(), "all_done": True}
    elif selected:
        # Selective fresh run: wipe only the chosen Sub-Domains, keep the rest of
        # data/raw/ and the resume ledger intact.
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
        else:
            return False   # unknown/"failed": _run_pool decides retry vs fail
        return True

    def _submit(pool, d):
        return pool.submit(worker.process_source, d, data_root=core.DATA_ROOT,
                           limit=limit, clean=False, crawl=crawl)

    try:
        _run_pool(descriptors, submit=_submit, on_result=_record, workers=workers,
                  source_timeout=source_timeout, summary=summary, ctx=ctx)
    finally:
        ledger.close()

    log.record_many(summary["ingest_rows"])
    ingestion_run.show_table()
    logger.info(f"ingest: done ok={summary['ok']} failed={summary['failed']} "
                f"skipped={summary['skipped']} rejected={summary['rejected']} "
                f"timed_out={summary['timed_out']}")
    return summary


# ── Stage 3: Clean (whole tree + cross-source dedup) ──────────────────────────

def run_clean(*, keep_raw: bool = True, limit: int | None = None,
              resume: bool = False, drop_non_english: bool = False,
              domains: list[str] | None = None) -> dict:
    """Clean the whole ``data/raw/`` tree into ``data/clean/``, then dedup (stage 3).

    The clean stage of the five-stage pipeline. Cleans every fetched source in one
    pass (per-source transforms, per-source dedup disabled), writes
    ``logs/clean_report.csv``, then runs the single deterministic cross-source
    dedup pass (:func:`cleaning.pipeline.final_global_dedup`). ``data/raw/`` is
    **retained** after cleaning by default; pass ``keep_raw=False`` to delete it.
    Fresh (non-resume) wipes ``data/clean/`` and the dedup + report state first;
    ``resume`` continues a partial dedup pass.

    ``domains`` restricts the run to those Sub-Domains (a *selective* clean): only
    their ``data/raw/<domain>/`` subtrees are cleaned, a fresh run wipes only those
    Sub-Domains' ``data/clean/<domain>/`` folders (every other Sub-Domain's cleaned
    output is preserved), and ``keep_raw=False`` deletes only the selected raw
    folders. The cross-source dedup pass still runs over the whole ``data/clean/``
    tree so cross-domain duplicates are resolved.

    Cross-source dedup folds into this stage (there is no separate "dedup" stage).
    """
    raw_root = core.RAW_DATA
    selected = list(domains) if domains else None
    if not resume:
        cleaning_pipeline.reset_dedup_state()
        if selected:
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

    # clean_one_source scans find_input_files under the given dir with the
    # process-cached transformers (deduper disabled); passing the raw root cleans
    # the whole tree, passing one Sub-Domain folder cleans just that Sub-Domain.
    # Cross-source dedup follows, over the whole clean tree either way.
    if selected:
        logger.info(f"clean: selective {sorted(set(selected))} -> "
                    f"{cleaning_pipeline.OUT_CLEAN_DATA}")
        rows: list[dict] = []
        for dom in selected:
            dom_dir = os.path.join(raw_root, dom)
            if os.path.isdir(dom_dir):
                rows += cleaning_pipeline.clean_one_source(
                    dom_dir, raw_root=raw_root,
                    clean_data_dir=cleaning_pipeline.OUT_CLEAN_DATA, limit=limit,
                    drop_non_english=drop_non_english)
            else:
                logger.warning(f"clean: no raw data for sub-domain {dom!r}")
    else:
        logger.info(f"clean: {raw_root} -> {cleaning_pipeline.OUT_CLEAN_DATA}")
        rows = cleaning_pipeline.clean_one_source(
            raw_root, raw_root=raw_root,
            clean_data_dir=cleaning_pipeline.OUT_CLEAN_DATA, limit=limit,
            drop_non_english=drop_non_english)
    if rows:
        cleaning_pipeline._write_report(rows)

    dedup = cleaning_pipeline.final_global_dedup(
        cleaning_pipeline.OUT_CLEAN_DATA, resume=resume)

    if not keep_raw:
        if selected:
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
    """Clean the whole existing data/raw/ tree in one sequential pass (dedup off).

    Used by the Prefect flow, which fetches via its own mapped tasks and then
    needs a single clean pass. Deterministic cross-source dedup is left to
    `final_global_dedup`. The CLI clean stage uses `run_clean` instead.
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
    logger.info(f"clean_raw_tree: {len(rows)} files, in={total_in} out={total_out}")
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


# ── Combined Pipeline ─────────────────────────────────────────────────────────

def run_v2_pipeline(spec: str | None = None, *,
                    workers: int | None = None,
                    resume: bool = False,
                    keep_raw: bool = True,
                    limit: int | None = None,
                    source_timeout: float = DEFAULT_SOURCE_TIMEOUT_S,
                    max_source_gb: float | None = None,
                    drop_non_english: bool = False,
                    crawl: bool = True,
                    enforce_eda: bool = True,
                    normalize: bool = True) -> dict:
    """Run the five stages in sequence: ingest -> clean -> EDA -> schema.

    Physically separate stages (no ingest/clean overlap): ingest fetches every
    source to data/raw/, clean cleans the whole tree and cross-source dedups into
    data/clean/ (data/raw/ is retained by default; pass keep_raw=False to delete
    it), then the deep EDA gate and schema normalization run.

    Parameters
    ----------
    spec : str | None
        Path to sources CSV; uses default catalog when omitted.
    workers : int | None
        Ingest process pool size; defaults to os.cpu_count().
    resume : bool
        Skip sources already fetched in a prior run (ingest) and continue a partial
        dedup pass (clean).
    keep_raw : bool
        Keep data/raw/ after cleaning (default True); pass False to delete it.
    limit : int | None
        Cap records per file (for smoke tests).
    source_timeout : float
        Per-source wall-clock budget (seconds); a hung source is abandoned.
    crawl : bool
        Fetch website (crawl) sources during ingest (default True); False records
        them as skipped without crawling.
    enforce_eda : bool
        Raise SufficiencyError on EDA blockers (default True).
    normalize : bool
        Run schema normalization; False stops after EDA.
    """
    from ..eda import SufficiencyError

    # Stage 2: fetch every source to data/raw/ (no cleaning).
    ingest_result = run_ingest(spec, workers=workers, resume=resume, limit=limit,
                               source_timeout=source_timeout,
                               max_source_gb=max_source_gb, crawl=crawl)

    # Stage 3: clean the whole raw tree + cross-source dedup -> data/clean/.
    clean_result = run_clean(keep_raw=keep_raw, limit=limit, resume=resume,
                             drop_non_english=drop_non_english)

    # Stage 4: deep global EDA sufficiency gate.
    try:
        eda_result = run_deep_eda(enforce=enforce_eda)
    except SufficiencyError as exc:
        logger.error(str(exc))
        print("Pipeline halted at the EDA sufficiency gate - "
              "address the blockers above and re-run.")
        return {"phase": "eda", "error": str(exc), "ingest": ingest_result,
                "clean": clean_result}

    # Stage 5: schema normalization (append to final).
    norm_result = {}
    if normalize:
        # Fresh build: clean regenerates data/clean/ upstream, so normalize fresh
        # (resume=False) instead of appending/deduping against a stale dataset.
        norm_result = run_normalize(resume=resume)

    return {"phase": "complete", "ingest": ingest_result, "clean": clean_result,
            "eda": eda_result, "normalize": norm_result}



