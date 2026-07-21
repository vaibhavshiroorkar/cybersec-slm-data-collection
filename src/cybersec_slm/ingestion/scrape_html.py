#!/usr/bin/env python3
"""Crawl openly-licensed cybersecurity websites -> JSONL (one record per page).

The crawl engine is Scrapy, run as an isolated subprocess
(:mod:`cybersec_slm.ingestion.crawl_runner`) so its Twisted reactor never
conflicts with the ingestion ProcessPoolExecutor. This module keeps the
``crawl`` seam the per-source worker calls
(:func:`cybersec_slm.ingestion.worker.process_source`): it launches the runner,
then records provenance + the ingest-log row exactly as the other scrapers do.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from urllib.parse import urlparse

from . import crawl_runner
from .common import (
    HEADERS,
    ONE_MB,
    RAW_DATA,
    category_of,
    count_lines,
    logger,
    sha256_file,
)

BASE = RAW_DATA
UA = HEADERS["User-Agent"]
BASE_CLOSE_TIMEOUT_S = 120   # floor: even a tiny site gets this much budget
PER_PAGE_TIMEOUT_S = 3       # extra seconds of budget per page in max_pages
MAX_CLOSE_TIMEOUT_S = 1800   # ceiling: one huge site can't hog a worker slot
SUBPROC_BUFFER_S = 120       # subprocess.run budget = close timeout + buffer
DOWNLOAD_DELAY_S = 0.3       # politeness delay between requests
CONCURRENCY_PER_DOMAIN = 4   # in-flight requests per domain (see crawl_runner)

def _close_timeout_for(max_pages: int) -> int:
    """Scale the in-child crawl budget to the site's page cap.

    A flat 600s budget for every site means a 20-page source and a 500-page
    source both wait up to 10 minutes before CLOSESPIDER_TIMEOUT fires: the
    small one holds a worker slot idle long after it's actually done, and the
    large one may still be cut off mid-crawl. Scaling by max_pages fixes both,
    within a floor (very small crawls still get a fair shot) and a ceiling (a
    misconfigured max_pages can't monopolize a worker indefinitely).
    """
    return min(MAX_CLOSE_TIMEOUT_S,
               max(BASE_CLOSE_TIMEOUT_S, int(max_pages) * PER_PAGE_TIMEOUT_S))


def _source_file(folder: str, title: str, url: str, lic: str) -> None:
    with open(os.path.join(folder, "_SOURCE.json"), "w", encoding="utf-8") as f:
        json.dump({"source": title, "url": url, "license": lic}, f, indent=2)


def _record_failed(log, *, slug, domain, desc, start_url, lic, status) -> None:
    log.record(kind="website", name=slug, category=category_of("website"),
               domain=domain, description=desc, source_url=start_url,
               origin_format="html", license=lic, status=status)


def crawl(domain, slug, start_url, lic, use_js, max_pages, allow_prefix, desc, log,
          extractor: str | None = None):
    """Crawl one site into JSONL.

    ``extractor`` picks how a page becomes text (see
    :mod:`cybersec_slm.ingestion.crawl_runner`): ``default`` strips known
    boilerplate tags and keeps the rest, ``trafilatura`` detects the main content.
    It rides in the JSON config the runner subprocess already reads, so choosing
    one needs no new plumbing. ``$CYBERSEC_SLM_EXTRACTOR`` sets it for a run
    without threading the flag through every caller.
    """
    folder = os.path.join(BASE, domain, slug)
    os.makedirs(folder, exist_ok=True)
    out = os.path.join(folder, slug + ".jsonl")
    close_timeout = _close_timeout_for(max_pages)
    cfg = {
        "start_url": start_url, "allow_prefix": allow_prefix,
        "max_pages": int(max_pages), "use_js": bool(use_js), "out_path": out,
        "user_agent": UA, "download_delay": DOWNLOAD_DELAY_S,
        "concurrency_per_domain": CONCURRENCY_PER_DOMAIN,
        "close_timeout": close_timeout, "license": lic, "description": desc,
        # trafilatura does real main-content detection instead of "everything
        # not under one of 8 known boilerplate tags", so it's the default now;
        # extract_trafilatura() falls back to extract_default() on its own if
        # the optional dependency isn't installed, so this never hard-fails.
        "extractor": (extractor or os.environ.get("CYBERSEC_SLM_EXTRACTOR")
                      or crawl_runner.EXTRACTOR_TRAFILATURA),
    }
    logger.info(f"=== WEBSITE: {desc} ({urlparse(start_url).netloc}) ===")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "cybersec_slm.ingestion.crawl_runner",
             json.dumps(cfg)],
            capture_output=True, text=True,
            timeout=close_timeout + SUBPROC_BUFFER_S)
    except subprocess.TimeoutExpired:
        logger.error(f"  crawl timed out: {slug}")
        _record_failed(log, slug=slug, domain=domain, desc=desc,
                       start_url=start_url, lic=lic, status="failed: timeout")
        return

    if (proc.returncode != 0 or not os.path.exists(out)
            or os.path.getsize(out) == 0):
        logger.error(f"  crawl failed: {slug} (rc={proc.returncode})")
        _record_failed(log, slug=slug, domain=domain, desc=desc,
                       start_url=start_url, lic=lic,
                       status=f"failed: crawl rc={proc.returncode}")
        return

    _source_file(folder, desc, start_url, lic)
    n = count_lines(out)
    size = os.path.getsize(out)
    logger.info(f"  {slug}: {n} pages, {size / ONE_MB:.2f} MB")
    log.record(kind="website", name=slug, category=category_of("website"),
               domain=domain, description=desc, source_url=start_url,
               origin_format="html", jsonl_mb=round(size / ONE_MB, 1), rows=n,
               sha256=sha256_file(out), license=lic, status="ok")