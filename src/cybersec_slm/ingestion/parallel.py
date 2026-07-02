#!/usr/bin/env python3
"""Parallel streaming orchestrator.

Runs many sources concurrently across CPU cores. Each source flows
fetch -> JSONL -> clean -> data/clean/ -> delete raw inside a worker process
(:func:`cybersec_slm.ingestion.worker.process_source`). The parent owns the
SQLite ingest log (workers buffer rows and return them, so SQLite is only ever
written from one process), and runs the single cross-source dedup pass after the
pool drains.

    cybersec-slm run --sources sources/Sources.csv --workers 4
"""

from __future__ import annotations

import multiprocessing as mp
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool

from .. import core
from ..cleaning import pipeline
from . import run as ingestion_run
from . import sources, worker
from .allowlist import descriptor_key
from .common import IngestLog, logger

# Append-only ledger of sources fully fetched+cleaned this build. `--resume` reads
# it to skip work that already succeeded (avoids re-downloading multi-GB sources).
COMPLETED_LEDGER = os.path.join(core.LOGS, "completed_sources.txt")


def _default_workers() -> int:
    return min(os.cpu_count() or 4, 8)


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


def run_streaming(spec: str | None = None, *,
                  workers: int | None = None, keep_raw: bool = False,
                  limit: int | None = None, final_dedup: bool = True,
                  resume: bool = False) -> None:
    """Fetch + clean every source in parallel; one final global dedup pass.

    `spec` is a local path to a sources CSV; when omitted the default catalog
    `sources/Sources.csv` (``sources.DEFAULT_CATALOG``) is used.

    ``resume=True`` skips sources already fetched+cleaned in a prior run (recorded
    in ``COMPLETED_LEDGER``, keyed by ``descriptor_key``) and resumes the final
    dedup pass, so an interrupted build restarts without re-downloading. A fresh
    run (default) resets the ledger and dedup checkpoint so nothing is silently
    skipped.
    """
    # Pin the data root so spawned workers resolve the same data/raw + data/clean
    # paths as the parent (core.DATA_ROOT is frozen at import from this value).
    os.environ["CYBERSEC_SLM_DATA_ROOT"] = core.DATA_ROOT

    descriptors = sources.load_descriptors(spec or sources.DEFAULT_CATALOG)
    if not descriptors:
        logger.warning("no sources to process")
        return

    if resume:
        done_keys = _load_completed(COMPLETED_LEDGER)
        n_before = len(descriptors)
        descriptors = [d for d in descriptors if descriptor_key(d) not in done_keys]
        n_skip = n_before - len(descriptors)
        if n_skip:
            logger.info(f"resume: skipping {n_skip} already-complete sources "
                        f"({len(descriptors)} left to process)")
        if not descriptors:
            # Everything is already fetched+cleaned; just finish any interrupted
            # dedup pass over data/clean/ and report.
            logger.info("resume: all sources already complete")
            if final_dedup:
                pipeline.final_global_dedup(core.CLEAN_DATA, resume=True)
            ingestion_run.show_table()
            return
    else:
        _reset_completed(COMPLETED_LEDGER)      # fresh run: never skip silently
        pipeline.reset_dedup_state()

    workers = workers or _default_workers()
    logger.info(f"streaming {len(descriptors)} sources with {workers} workers "
                f"-> {core.CLEAN_DATA}")

    log = IngestLog()                       # parent-only SQLite writer
    clean_rows: list[dict] = []
    ingest_rows: list[dict] = []            # buffered, written in one transaction
    ok = failed = skipped = 0
    ctx = mp.get_context("spawn")
    # Append each source's key as it lands so a crash mid-run still leaves a
    # resumable ledger; failed sources are never recorded, so they retry.
    os.makedirs(core.LOGS, exist_ok=True)
    ledger = open(COMPLETED_LEDGER, "a", encoding="utf-8")

    try:
        with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as ex:
            futs = {ex.submit(worker.process_source, d, data_root=core.DATA_ROOT,
                              clean_data_dir=core.CLEAN_DATA, keep_raw=keep_raw,
                              limit=limit): d for d in descriptors}
            for fut in as_completed(futs):
                d = futs[fut]
                label = d.get("ref") or d.get("slug") or d.get("kind")
                try:
                    meta = fut.result()
                except Exception as ex2:        # worker process died hard
                    failed += 1
                    logger.error(f"  worker crashed for {label}: "
                                 f"{type(ex2).__name__}: {ex2}")
                    continue
                ingest_rows.extend(meta.get("ingest_rows", []))
                clean_rows.extend(meta.get("clean_report_rows", []))
                status = meta.get("status")
                if status == "ok":
                    ok += 1
                elif status == "skipped":
                    skipped += 1
                else:
                    failed += 1
                if status in ("ok", "skipped"):
                    ledger.write(descriptor_key(d) + "\n")
                    ledger.flush()
    except BrokenProcessPool as ex2:
        logger.error(f"process pool broke: {ex2}")
    finally:
        ledger.close()

    logger.info(f"streaming done: ok={ok} failed={failed} skipped={skipped}")

    log.record_many(ingest_rows)            # one transaction for the whole run
    if final_dedup:
        pipeline.final_global_dedup(core.CLEAN_DATA, resume=resume)
    if clean_rows:
        pipeline._write_report(clean_rows)
    ingestion_run.show_table()
