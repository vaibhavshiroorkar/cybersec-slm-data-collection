#!/usr/bin/env python3
"""Per-source streaming worker: fetch -> JSONL -> clean -> delete raw.

`process_source` is a top-level (picklable) function so it can run inside a
``ProcessPoolExecutor``. Each call handles ONE source end to end and is fully
isolated — it never touches the shared SQLite ingest log (it buffers rows in a
:class:`~cybersec_slm.extraction.common._Collector` and returns them for the
parent to write) and it runs cleaning with global dedup disabled (cross-source
dedup is a single final pass in the parent). One bad source returns a
``status="failed"`` dict instead of crashing the pool.
"""

from __future__ import annotations

import os
import shutil

from ..core import CLEAN_DATA, RAW_DATA, logger
from . import fetch, scrape, scrape_html
from .allowlist import descriptor_key, is_allowed
from .common import _Collector


def _fetch_one(descriptor: dict, log) -> str:
    """Run the matching handler for `descriptor`; return the raw source folder."""
    kind = descriptor["kind"]
    domain = descriptor["domain"]

    if kind in ("hf", "kaggle", "url", "github"):
        ref = descriptor["ref"]
        name = ref.split("/")[-1]
        owner = ref.split("/")[0] if "/" in ref and kind in ("hf", "kaggle") else name
        folder = fetch._folder(domain, owner, name, {owner: 1})
        lic, desc = descriptor["license"], descriptor["description"]
        if kind == "hf":
            fetch.fetch_hf(ref, domain, desc, lic, folder, log)
        elif kind == "kaggle":
            fetch.fetch_kaggle(ref, domain, desc, lic, folder, log)
        else:
            fetch.fetch_url(descriptor["url"], domain, desc, lic, folder, log, kind=kind)
        return folder

    slug = descriptor["slug"]
    folder = os.path.join(RAW_DATA, domain, slug)
    if kind == "pdf":
        scrape.scrape_pdf(domain, slug, descriptor["title"], descriptor["license"],
                          descriptor["url"], log)
    elif kind == "feed":
        scrape.scrape_feed(domain, slug, descriptor["title"], descriptor["license"],
                           descriptor["url"], descriptor["json_key"], log)
    elif kind == "website":
        scrape_html.crawl(domain, slug, descriptor["start_url"], descriptor["license"],
                          descriptor["use_js"], descriptor["max_pages"],
                          descriptor["allow_prefix"], descriptor["description"], log)
    else:
        raise ValueError(f"unknown source kind: {kind}")
    return folder


def process_source(descriptor: dict, *, data_root: str | None = None,
                   clean_data_dir: str | None = None, keep_raw: bool = False,
                   limit: int | None = None) -> dict:
    """Fetch one source, clean it into clean_data/, delete its raw files.

    Returns ``{descriptor, status, error, folder, ingest_rows,
    clean_report_rows}``. ``ingest_rows`` are replayed into the real ingest log
    by the parent; ``clean_report_rows`` feed the consolidated clean report.
    """
    from ..cleaning import pipeline

    clean_data_dir = clean_data_dir or CLEAN_DATA
    collector = _Collector()
    result = {"descriptor": descriptor, "status": "ok", "error": None,
              "folder": None, "ingest_rows": [], "clean_report_rows": []}
    label = descriptor.get("ref") or descriptor.get("slug") or descriptor.get("kind")

    # Allowlist gate (anti-poisoning): never fetch a source the team has not
    # explicitly approved. Skipped sources are logged + recorded, not fetched.
    allowed, reason = is_allowed(descriptor)
    if not allowed:
        result["status"] = "skipped"
        result["error"] = f"allowlist: {reason}"
        logger.warning(f"  SKIPPED (allowlist {reason}) {descriptor_key(descriptor)}")
        collector.record(kind=descriptor.get("kind"), name=label,
                         domain=descriptor.get("domain"),
                         source_url=descriptor.get("url") or descriptor.get("start_url"),
                         license=descriptor.get("license"),
                         status=f"skipped:allowlist:{reason}")
        result["ingest_rows"] = collector.rows
        return result
    try:
        logger.info(f"=== source: {descriptor['kind']} {label} ===")
        folder = _fetch_one(descriptor, collector)
        result["folder"] = folder
        result["ingest_rows"] = collector.rows

        if os.path.isdir(folder):
            result["clean_report_rows"] = pipeline.clean_one_source(
                folder, raw_root=RAW_DATA, clean_data_dir=clean_data_dir, limit=limit)
            if not keep_raw:
                shutil.rmtree(folder, ignore_errors=True)
    except Exception as ex:  # isolate: never crash the pool over one source
        result["status"] = "failed"
        result["error"] = f"{type(ex).__name__}: {ex}"
        result["ingest_rows"] = collector.rows
        logger.error(f"  FAILED {label}: {result['error']}")
    return result
