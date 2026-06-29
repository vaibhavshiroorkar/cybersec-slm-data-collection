#!/usr/bin/env python3
"""Extraction orchestrator + final-table reporter."""

from __future__ import annotations

import os
import sys

from ..core import LOGS
from .common import IngestLog, logger

COLS = ["name", "domain", "description", "category", "source_url",
        "origin_format", "orig_mb", "jsonl_mb", "rows", "license"]
HEADERS = ["Name", "Sub-Domain", "Description", "Category", "Dataset Link",
           "Original Format", "Original Size (MB)", "JSONL Size (MB)",
           "Total Lines", "License"]


def show_table() -> None:
    import pandas as pd

    from .common import category_of
    log = IngestLog()
    df = log.table()
    if df.empty:
        logger.info("ingest log is empty — run fetch/scrape first.")
        return
    log.export_ledger()                 # provenance ledger -> logs/provenance/ledger.csv
    df["category"] = df["kind"].apply(category_of)
    df = df.drop_duplicates(subset=["name", "domain"], keep="last")
    out = df[COLS].rename(columns=dict(zip(COLS, HEADERS, strict=False)))
    out_path = os.path.join(LOGS, "final_table.csv")
    out.to_csv(out_path, index=False)
    with pd.option_context("display.max_rows", None, "display.width", 200):
        print(out.to_string(index=False))
    ok = (df["status"] == "ok").sum()
    skip = df["status"].str.startswith("skipped").sum()
    fail = df["status"].str.startswith("failed").sum()
    print(f"\nrows: {len(out)}  | ok: {ok}  skipped(>5GB): {skip}  failed: {fail}")
    print(f"written: {out_path}")


def run(cmd: str = "all", nvd_key: str | None = None) -> None:
    """Run an extraction command: scrape | fetch | html | nvd | all | table."""
    if cmd == "table":
        show_table()
        return
    log = IngestLog()
    if cmd in ("scrape", "all"):
        from . import scrape
        scrape.run(log)
    if cmd in ("fetch", "all"):
        from . import fetch
        from .manifest import DATASETS
        fetch.run(DATASETS, log)
    if cmd in ("html", "crawl", "all"):
        from . import scrape_html
        scrape_html.run(log)
    if cmd in ("nvd", "all"):
        from . import fetch_nvd
        fetch_nvd.run(log, api_key=nvd_key or os.environ.get("NVD_API_KEY"))
    logger.info("=== EXTRACTION DONE ===")
    show_table()


def main() -> None:
    run(sys.argv[1] if len(sys.argv) > 1 else "all")


if __name__ == "__main__":
    main()
