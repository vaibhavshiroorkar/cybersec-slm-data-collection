#!/usr/bin/env python3
"""Orchestrate keyword search -> dedup -> append for the sourcing stage.

Pipeline per run:

    for each Sub-Domain (optionally filtered):
        for each keyword in that domain:
            search -> results
            for each result:
                build a catalog row (Sub-Domain assigned, fields inferred)
                drop if its link is already in Sources.csv, or seen this run
    write the survivors to a local review CSV (always) and, unless --dry-run,
    append them to the catalog ``sources/Sources.csv``.

The per-run review CSV under ``logs/discovered/`` is a safety net: even a live
run leaves a record of exactly what was added.
"""

from __future__ import annotations

import csv
import os
from datetime import date

from ..core import DATA_ROOT, LOGS, logger
from . import keywords as kw
from .row import SHEET_COLUMNS, build_row, row_to_list
from .search import SearchError, google_search
from .sheet import append_rows, existing_links, normalize_url

# The catalog this pipeline curates (a local CSV at the repo root).
DEFAULT_CATALOG = os.path.join(DATA_ROOT, "sources", "Sources.csv")


def _write_csv(rows: list[dict[str, str]], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(SHEET_COLUMNS)
        for r in rows:
            w.writerow(row_to_list(r))


def discover(csv_path: str | None = None, *, domains: list[str] | None = None,
             per_keyword: int = 5, max_per_domain: int | None = None,
             mode: str = "datasets", dry_run: bool = False,
             out_csv: str | None = None, api_key: str | None = None,
             cse_id: str | None = None, client=None) -> dict:
    """Run sourcing and return a summary dict.

    ``mode`` selects the keyword catalog: ``datasets`` (corpora/repos), ``text``
    (articles/docs/writeups), or ``both``. ``client`` is an optional shared
    ``httpx.Client`` (search reuses it).
    Returns ``{"found", "new", "appended", "csv", "by_domain"}``.
    """
    csv_path = csv_path or DEFAULT_CATALOG

    selected = domains or list(kw.DOMAIN_KEYWORDS)
    unknown = [d for d in selected if d not in kw.DOMAIN_KEYWORDS]
    if unknown:
        raise ValueError(f"unknown Sub-Domain(s): {unknown}. "
                         f"Valid: {list(kw.DOMAIN_KEYWORDS)}")

    logger.info(f"source: reading existing links from {csv_path}")
    seen = existing_links(csv_path)
    logger.info(f"source: {len(seen)} links already in the catalog")

    today = date.today().strftime("%d/%m/%Y")
    new_rows: list[dict[str, str]] = []
    found = 0
    by_domain: dict[str, int] = {}

    for domain in selected:
        added_here = 0
        for kwset, qualifier in kw.keyword_sets(mode):
            if max_per_domain is not None and added_here >= max_per_domain:
                break
            for keyword in kwset.get(domain, []):
                if max_per_domain is not None and added_here >= max_per_domain:
                    break
                query = f"{keyword} {qualifier}".strip()
                try:
                    results = google_search(query, api_key=api_key, cse_id=cse_id,
                                            num=min(per_keyword, 10), client=client)
                except SearchError as e:
                    logger.error(f"source: search failed for {query!r}: {e}")
                    raise
                for res in results:
                    found += 1
                    norm = normalize_url(res.link)
                    if not norm or norm in seen:
                        continue
                    seen.add(norm)                 # also dedup within this run
                    new_rows.append(build_row(res, domain, today=today))
                    added_here += 1
                    if max_per_domain is not None and added_here >= max_per_domain:
                        break
        by_domain[domain] = added_here
        logger.info(f"source: {domain}: {added_here} new")

    review_csv = out_csv or os.path.join(
        LOGS, "discovered", f"discovered-{date.today():%Y%m%d}.csv")
    _write_csv(new_rows, review_csv)
    logger.info(f"source: wrote {len(new_rows)} candidate rows -> {review_csv}")

    appended = 0
    if new_rows and not dry_run:
        appended = append_rows(csv_path, new_rows)
        logger.info(f"source: appended {appended} rows to {csv_path}")
    elif dry_run:
        logger.info("source: dry-run, not appending to the catalog")

    return {"found": found, "new": len(new_rows), "appended": appended,
            "csv": review_csv, "by_domain": by_domain}
