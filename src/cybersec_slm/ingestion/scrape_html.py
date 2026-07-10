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
CLOSE_TIMEOUT_S = 600        # Scrapy CLOSESPIDER_TIMEOUT (in-child budget)
SUBPROC_BUFFER_S = 120       # subprocess.run budget = close timeout + buffer
DOWNLOAD_DELAY_S = 0.3       # politeness delay between requests


def _source_file(folder: str, title: str, url: str, lic: str) -> None:
    with open(os.path.join(folder, "_SOURCE.json"), "w", encoding="utf-8") as f:
        json.dump({"source": title, "url": url, "license": lic}, f, indent=2)


def _record_failed(log, *, slug, domain, desc, start_url, lic, status) -> None:
    log.record(kind="website", name=slug, category=category_of("website"),
               domain=domain, description=desc, source_url=start_url,
               origin_format="html", license=lic, status=status)


def crawl(domain, slug, start_url, lic, use_js, max_pages, allow_prefix, desc, log):
    folder = os.path.join(BASE, domain, slug)
    os.makedirs(folder, exist_ok=True)
    out = os.path.join(folder, slug + ".jsonl")
    cfg = {
        "start_url": start_url, "allow_prefix": allow_prefix,
        "max_pages": int(max_pages), "use_js": bool(use_js), "out_path": out,
        "user_agent": UA, "download_delay": DOWNLOAD_DELAY_S,
        "close_timeout": CLOSE_TIMEOUT_S, "license": lic, "description": desc,
    }
    logger.info(f"=== WEBSITE: {desc} ({urlparse(start_url).netloc}) ===")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "cybersec_slm.ingestion.crawl_runner",
             json.dumps(cfg)],
            capture_output=True, text=True,
            timeout=CLOSE_TIMEOUT_S + SUBPROC_BUFFER_S)
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
