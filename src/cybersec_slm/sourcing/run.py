#!/usr/bin/env python3
"""Orchestrate keyword search -> dedup -> append for the sourcing stage.

Pipeline per run:

    for each Sub-Domain (optionally filtered):
        for each keyword in that domain:
            search (SearXNG) -> results
            for each result:
                build a catalog row (Sub-Domain assigned, fields inferred)
                drop if its link is already in Sources.csv, or seen this run
    write the survivors to a local review CSV (always) and, unless --dry-run,
    append them to the catalog ``sources/Sources.csv``.

Two independent caps bound the run: ``max_per_domain`` (new rows kept per
Sub-Domain) and ``max_total`` (new rows kept across the whole run); the run stops
as soon as either is hit. The keyword catalog is the persisted, editable one from
:mod:`cybersec_slm.sourcing.catalog`.

The per-run review CSV under ``logs/discovered/`` is a safety net (even a live run
leaves a record of exactly what was added); a sidecar ``summary-*.json`` records
the per-keyword hit/new counts so the dashboard can show which keywords ran.
"""

from __future__ import annotations

import csv
import json
import os
from datetime import date

from ..core import DATA_ROOT, LOGS, logger
from . import catalog
from .enrich import Enricher
from .row import SHEET_COLUMNS, build_row, row_to_list
from .search import SearchError, searxng_search
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


def _write_summary(summary: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)


def discover(csv_path: str | None = None, *, domains: list[str] | None = None,
             per_keyword: int = 5, max_per_domain: int | None = None,
             max_total: int | None = None, mode: str = "datasets",
             dry_run: bool = False, out_csv: str | None = None,
             base_url: str | None = None, language: str = "en", client=None,
             enrich: bool = True) -> dict:
    """Run sourcing and return a summary dict.

    ``mode`` selects the keyword catalog: ``datasets`` (corpora/repos), ``text``
    (articles/docs/writeups), or ``both``. ``max_per_domain`` caps new rows per
    Sub-Domain; ``max_total`` caps new rows across the whole run; the run stops
    when either is hit. ``base_url`` overrides ``$SEARXNG_URL``; ``client`` is an
    optional shared ``httpx.Client``.

    With ``enrich`` (default), each kept row is passed through
    :class:`sourcing.enrich.Enricher`, which fills its metadata columns (size,
    license, last updated, author, popularity, tags) from the source host. It is
    best-effort - a failed lookup leaves the field blank and never aborts the run.

    Returns ``{"found", "new", "appended", "csv", "by_domain", "by_keyword"}``.
    """
    csv_path = csv_path or DEFAULT_CATALOG
    enricher = Enricher(client=client) if enrich else None

    cat = catalog.load()
    all_domains = catalog.subdomains(cat)
    selected = domains or all_domains
    unknown = [d for d in selected if d not in cat]
    if unknown:
        raise ValueError(f"unknown Sub-Domain(s): {unknown}. Valid: {all_domains}")

    logger.info(f"source: reading existing links from {csv_path}")
    seen = existing_links(csv_path)
    logger.info(f"source: {len(seen)} links already in the catalog")

    today = date.today().strftime("%d/%m/%Y")
    new_rows: list[dict[str, str]] = []
    found = 0
    by_domain: dict[str, int] = {}
    by_keyword: list[dict] = []
    stop = False

    for domain in selected:
        if stop:
            break
        added_here = 0
        for kwdict, qualifier in catalog.keyword_sets(mode, cat):
            if stop or (max_per_domain is not None and added_here >= max_per_domain):
                break
            for keyword in kwdict.get(domain, []):
                if max_per_domain is not None and added_here >= max_per_domain:
                    break
                if max_total is not None and len(new_rows) >= max_total:
                    stop = True
                    break
                query = f"{keyword} {qualifier}".strip()
                try:
                    results = searxng_search(query, url=base_url,
                                             num=per_keyword, language=language,
                                             client=client)
                except SearchError as e:
                    logger.error(f"source: search failed for {query!r}: {e}")
                    raise
                kw_new = 0
                for res in results:
                    found += 1
                    norm = normalize_url(res.link)
                    if not norm or norm in seen:
                        continue
                    seen.add(norm)                 # also dedup within this run
                    row = build_row(res, domain, today=today)
                    if enricher is not None:
                        enricher.enrich(row)
                    new_rows.append(row)
                    added_here += 1
                    kw_new += 1
                    if max_per_domain is not None and added_here >= max_per_domain:
                        break
                    if max_total is not None and len(new_rows) >= max_total:
                        stop = True
                        break
                by_keyword.append({"domain": domain, "keyword": keyword,
                                   "hits": len(results), "new": kw_new})
        by_domain[domain] = added_here
        logger.info(f"source: {domain}: {added_here} new")

    stamp = f"{date.today():%Y%m%d}"
    review_csv = out_csv or os.path.join(LOGS, "discovered", f"discovered-{stamp}.csv")
    _write_csv(new_rows, review_csv)
    logger.info(f"source: wrote {len(new_rows)} candidate rows -> {review_csv}")

    appended = 0
    if new_rows and not dry_run:
        appended = append_rows(csv_path, new_rows)
        logger.info(f"source: appended {appended} rows to {csv_path}")
    elif dry_run:
        logger.info("source: dry-run, not appending to the catalog")

    summary = {"found": found, "new": len(new_rows), "appended": appended,
               "csv": review_csv, "mode": mode, "domains": selected,
               "by_domain": by_domain, "by_keyword": by_keyword}
    _write_summary(summary, os.path.join(LOGS, "discovered", f"summary-{stamp}.json"))
    return summary
