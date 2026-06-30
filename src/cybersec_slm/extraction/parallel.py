#!/usr/bin/env python3
"""Parallel streaming orchestrator.

Runs many sources concurrently across CPU cores. Each source flows
fetch -> JSONL -> clean -> data/clean/ -> delete raw inside a worker process
(:func:`cybersec_slm.extraction.worker.process_source`). The parent owns the
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
from . import run as extraction_run
from . import sources, worker
from .common import IngestLog, logger


def _default_workers() -> int:
    return min(os.cpu_count() or 4, 8)


def run_streaming(spec: str | None = None, *,
                  workers: int | None = None, keep_raw: bool = False,
                  limit: int | None = None, final_dedup: bool = True) -> None:
    """Fetch + clean every source in parallel; one final global dedup pass.

    `spec` is a local path to a sources CSV; when omitted the default catalog
    `sources/Sources.csv` (``sources.DEFAULT_CATALOG``) is used.
    """
    # Pin the data root so spawned workers resolve the same data/raw + data/clean
    # paths as the parent (core.DATA_ROOT is frozen at import from this value).
    os.environ["CYBERSEC_SLM_DATA_ROOT"] = core.DATA_ROOT

    descriptors = sources.load_descriptors(spec or sources.DEFAULT_CATALOG)
    if not descriptors:
        logger.warning("no sources to process")
        return

    workers = workers or _default_workers()
    logger.info(f"streaming {len(descriptors)} sources with {workers} workers "
                f"-> {core.CLEAN_DATA}")

    log = IngestLog()                       # parent-only SQLite writer
    clean_rows: list[dict] = []
    ok = failed = skipped = 0
    ctx = mp.get_context("spawn")

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
                for row in meta.get("ingest_rows", []):
                    log.record(**row)            # serialized: parent only
                clean_rows.extend(meta.get("clean_report_rows", []))
                status = meta.get("status")
                if status == "ok":
                    ok += 1
                elif status == "skipped":
                    skipped += 1
                else:
                    failed += 1
    except BrokenProcessPool as ex2:
        logger.error(f"process pool broke: {ex2}")

    logger.info(f"streaming done: ok={ok} failed={failed} skipped={skipped}")

    if final_dedup:
        pipeline.final_global_dedup(core.CLEAN_DATA)
    if clean_rows:
        pipeline._write_report(clean_rows)
    extraction_run.show_table()
