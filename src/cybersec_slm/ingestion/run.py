#!/usr/bin/env python3
"""Final-table reporter for the ingest log (shared by the streaming path)."""

from __future__ import annotations

import os

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
        try:
            print(out.to_string(index=False))
        except UnicodeEncodeError:
            print(out.to_string(index=False).encode("ascii", errors="replace").decode("ascii"))
    ok = (df["status"] == "ok").sum()
    skip = df["status"].str.startswith("skipped").sum()
    fail = df["status"].str.startswith("failed").sum()
    print(f"\nrows: {len(out)}  | ok: {ok}  skipped(>5GB): {skip}  failed: {fail}")
    print(f"written: {out_path}")
