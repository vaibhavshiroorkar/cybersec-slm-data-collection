#!/usr/bin/env python3
"""Orchestrate keyword search -> dedup -> append for the discovery stage.

Pipeline per run:

    for each Sub-Domain (optionally filtered):
        for each keyword in that domain:
            search -> results
            for each result:
                build a sheet row (Sub-Domain assigned, fields inferred)
                drop if its link is already in the sheet, or seen this run
    write the survivors to a local CSV (always) and, unless --dry-run,
    append them to the live Google Sheet.

The local CSV is a review artifact and a safety net: even a live run leaves a
record under ``logs/discovered/`` of exactly what was added.
"""

from __future__ import annotations

import csv
import os
from datetime import date

from ..core import LOGS, logger
from . import keywords as kw
from .row import SHEET_COLUMNS, build_row, row_to_list
from .search import SearchError, google_search
from .sheet import append_rows, existing_links, extract_spreadsheet_id, normalize_url

# The finalized tracking sheet this pipeline curates.
DEFAULT_SHEET_URL = (
    "https://docs.google.com/spreadsheets/d/"
    "1RzHZqqPUw1-LtyOGi9b4QWfMesILEMf3qJVFSr8jw7Q/edit"
)


def _write_csv(rows: list[dict[str, str]], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(SHEET_COLUMNS)
        for r in rows:
            w.writerow(row_to_list(r))


def discover(sheet_url: str | None = None, *, domains: list[str] | None = None,
             per_keyword: int = 5, max_per_domain: int | None = None,
             mode: str = "datasets", dry_run: bool = False,
             out_csv: str | None = None, api_key: str | None = None,
             cse_id: str | None = None, creds_path: str | None = None,
             client=None) -> dict:
    """Run discovery and return a summary dict.

    ``mode`` selects the keyword catalog: ``datasets`` (corpora/repos), ``text``
    (articles/docs/writeups), or ``both``. ``client`` is an optional shared
    ``httpx.Client`` (search reuses it).
    Returns ``{"found", "new", "appended", "csv", "by_domain"}``.
    """
    sheet_url = sheet_url or DEFAULT_SHEET_URL
    spreadsheet_id = extract_spreadsheet_id(sheet_url)
    creds_path = creds_path or os.environ.get("GOOGLE_SHEETS_CREDENTIALS")

    selected = domains or list(kw.DOMAIN_KEYWORDS)
    unknown = [d for d in selected if d not in kw.DOMAIN_KEYWORDS]
    if unknown:
        raise ValueError(f"unknown Sub-Domain(s): {unknown}. "
                         f"Valid: {list(kw.DOMAIN_KEYWORDS)}")

    logger.info(f"discover: reading existing links from sheet {spreadsheet_id}")
    seen = existing_links(spreadsheet_id, client=client)
    logger.info(f"discover: {len(seen)} links already in the sheet")

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
                    logger.error(f"discover: search failed for {query!r}: {e}")
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
        logger.info(f"discover: {domain}: {added_here} new")

    csv_path = out_csv or os.path.join(
        LOGS, "discovered", f"discovered-{date.today():%Y%m%d}.csv")
    _write_csv(new_rows, csv_path)
    logger.info(f"discover: wrote {len(new_rows)} candidate rows -> {csv_path}")

    appended = 0
    if new_rows and not dry_run:
        appended = append_rows(
            spreadsheet_id, [row_to_list(r) for r in new_rows],
            creds_path=creds_path or "")
        logger.info(f"discover: appended {appended} rows to the sheet")
    elif dry_run:
        logger.info("discover: dry-run, not appending to the sheet")

    return {"found": found, "new": len(new_rows), "appended": appended,
            "csv": csv_path, "by_domain": by_domain}
