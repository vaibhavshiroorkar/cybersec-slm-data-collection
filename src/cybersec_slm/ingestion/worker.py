#!/usr/bin/env python3
"""Per-source ingestion worker: fetch -> JSONL -> light EDA gate.

`process_source` is a top-level (picklable) function so it can run inside a
``ProcessPoolExecutor``. Each call handles ONE source end to end and is fully
isolated — it never touches the shared SQLite ingest log (it buffers rows in a
:class:`~cybersec_slm.ingestion.common._Collector` and returns them for the
parent to write).

The worker fetches: it converts to JSONL and runs the light-EDA quality gate +
flag annotation. With ``clean=False`` (the ingest stage) it stops there and leaves
raw in place for the separate clean stage (``parallel.run_clean``). With
``clean=True`` it also cleans the source inline via
``cleaning.pipeline.clean_one_source``.

One bad source returns a ``status="failed"`` dict instead of crashing the pool.
"""

from __future__ import annotations

import os

from ..core import RAW_DATA, logger
from . import fetch, fetch_nvd, light_eda, rss, scrape, scrape_html
from .common import _Collector
from .license_gate import is_license_ok
from .sources import descriptor_key, synthetic_identities


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
    elif kind == "api":
        # NVD CVE 2.0 — paginated REST API (key only raises the rate limit).
        fetch_nvd.fetch_nvd(domain, slug, descriptor["title"], descriptor["license"],
                            descriptor["url"], log,
                            api_key=os.environ.get("NVD_API_KEY"))
    elif kind == "xml":
        scrape.scrape_cwe(domain, slug, descriptor["title"], descriptor["license"],
                          descriptor["url"], log)
    elif kind == "feed":
        scrape.scrape_feed(domain, slug, descriptor["title"], descriptor["license"],
                           descriptor["url"], descriptor["json_key"], log)
    elif kind == "rss":
        rss.scrape_rss(domain, slug, descriptor["title"], descriptor["license"],
                       descriptor["url"], log,
                       metadata_only=descriptor.get("metadata_only", False))
    elif kind == "website":
        scrape_html.crawl(domain, slug, descriptor["start_url"], descriptor["license"],
                          descriptor["use_js"], descriptor["max_pages"],
                          descriptor["allow_prefix"], descriptor["description"], log)
    else:
        raise ValueError(f"unknown source kind: {kind}")
    return folder


# Pre-load synthetic identities ONCE per worker process (not per source).
_synthetic_ids_cache: frozenset[str] | None = None


def _get_synthetic_ids() -> frozenset[str]:
    global _synthetic_ids_cache
    if _synthetic_ids_cache is None:
        _synthetic_ids_cache = synthetic_identities()
    return _synthetic_ids_cache


def process_source(
    descriptor: dict, *, data_root: str | None = None, limit: int | None = None,
    clean: bool = True, crawl: bool = True, scan_hazards: bool = True,
) -> dict:
    """Fetch one source, run the light EDA gate, and (optionally) clean it.

    Returns ``{descriptor, status, error, folder, ingest_rows,
    light_eda_report, flags, clean_rows}``.  ``ingest_rows`` are replayed into the
    real ingest log by the parent. With ``clean=False`` (the ingest stage) the
    worker stops after the gate and leaves the raw folder in place; the separate
    clean stage cleans the whole raw tree later. With ``crawl=False`` a website
    (crawl) source is recorded as skipped and never fetched. ``scan_hazards``
    controls the light-EDA gate's security-hazard scan (passed explicitly since
    this function runs in a spawned worker process, so a module-global toggle set
    in the parent would never reach it).
    """
    collector = _Collector()
    result = {"descriptor": descriptor, "status": "ok", "error": None,
              "folder": None, "ingest_rows": [], "light_eda_report": {},
              "clean_rows": [],
              "flags": {"synthetic": False, "license_risk": None,
                        "security_hazards": []}}
    label = descriptor.get("ref") or descriptor.get("slug") or descriptor.get("kind")

    # Crawler gate: with the crawler disabled for this run, website sources are
    # recorded as skipped (never fetched) so the rest of the run is unaffected.
    if not crawl and descriptor.get("kind") == "website":
        result["status"] = "skipped"
        result["error"] = "crawler disabled for this run"
        logger.info(f"  SKIPPED (crawler off) {descriptor_key(descriptor)}")
        collector.record(kind=descriptor.get("kind"), name=label,
                         domain=descriptor.get("domain"),
                         source_url=descriptor.get("start_url") or descriptor.get("url"),
                         license=descriptor.get("license"),
                         status="skipped:crawler-off")
        result["ingest_rows"] = collector.rows
        return result

    # License gate (commercial-only): never fetch a source we can't train on
    # commercially. Skipped sources are logged + recorded, not fetched.
    licensed, lreason = is_license_ok(descriptor)
    if not licensed:
        result["status"] = "skipped"
        result["error"] = f"license: {lreason}"
        result["flags"]["license_risk"] = lreason
        logger.warning(f"  SKIPPED (license {lreason}) {descriptor_key(descriptor)}")
        collector.record(kind=descriptor.get("kind"), name=label,
                         domain=descriptor.get("domain"),
                         source_url=descriptor.get("url") or descriptor.get("start_url"),
                         license=descriptor.get("license"),
                         status=f"skipped:license:{lreason}")
        result["ingest_rows"] = collector.rows
        return result
    try:
        logger.info(f"=== source: {descriptor['kind']} {label} ===")
        folder = _fetch_one(descriptor, collector)
        result["folder"] = folder
        result["ingest_rows"] = collector.rows

        # Light EDA gate: fast quality check + flag annotation
        if os.path.isdir(folder):
            syn_ids = _get_synthetic_ids()
            passed, leda_report = light_eda.assess_source(
                folder, descriptor, synthetic_ids=syn_ids, scan_hazards=scan_hazards)
            result["light_eda_report"] = leda_report
            result["flags"] = leda_report.get("flags", result["flags"])

            if not passed:
                result["status"] = "rejected"
                result["error"] = leda_report.get("reject_reason", "light EDA rejection")
                # Move rejected source into data/dropped/ with sidecar report
                light_eda.reject_source(folder, leda_report)
            elif clean:
                from ..cleaning.pipeline import clean_one_source
                result["clean_rows"] = clean_one_source(folder, limit=limit)
    except Exception as ex:  # isolate: never crash the pool over one source
        result["status"] = "failed"
        result["error"] = f"{type(ex).__name__}: {ex}"
        result["ingest_rows"] = collector.rows
        logger.error(f"  FAILED {label}: {result['error']}")
    except BaseException as ex:  # Rust panics (pyo3) surface here; don't kill the pool
        # Mark deterministic failures so the parent skips the retry queue.
        # NOTE: a true Rust panic aborts the worker process before this runs;
        # the parent then sees BrokenProcessPool and rebuilds the pool. This
        # branch only catches Python-level BaseException subclasses that escape
        # `Exception` (e.g. KeyboardInterrupt during shutdown).
        result["status"] = "failed"
        result["error"] = f"{type(ex).__name__}: {ex}"
        result["ingest_rows"] = collector.rows
        logger.error(f"  FAILED {label}: {result['error']}")
    return result
