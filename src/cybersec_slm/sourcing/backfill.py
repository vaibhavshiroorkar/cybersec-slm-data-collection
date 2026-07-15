#!/usr/bin/env python3
"""Backfill licenses onto existing catalog rows, then blacklist the red ones.

Discovery enriches only *new* rows, so a catalog grown before deep detection
existed (or over a rate-limited GitHub run) is full of blank licenses. This
stage walks ``sources/Sources.csv``, runs :func:`sourcing.license_detect.
detect_license` on every row whose License is blank / "Unknown", writes back
what it finds, and then hands the catalog to :func:`sourcing.blacklist.
move_flagged` so any now-confirmed-red source is relocated out of the catalog.

Best-effort and resumable by nature: a row detection can't resolve stays blank
and is simply picked up by the next run (e.g. once ``$GITHUB_TOKEN`` is set to
lift the GitHub rate limit). Progress is logged with the ``source:`` marker the
dashboard's phase-parser watches, and a ``logs/discovered/backfill-<date>.json``
summary records what happened.
"""

from __future__ import annotations

import json
import os
from datetime import date
from urllib.parse import urlparse

from ..core import DATA_ROOT, LOGS, logger
from . import blacklist
from .license_detect import detect_license
from .sheet import _link_column

DEFAULT_CATALOG = os.path.join(DATA_ROOT, "sources", "Sources.csv")

# Licenses that count as "not yet resolved" and so are (re)detected by default.
_UNRESOLVED = {"", "unknown", "to-verify", "n/a", "none", "tbd"}


def _needs_detection(value: str) -> bool:
    return str(value or "").strip().lower() in _UNRESOLVED


def _host(url: str) -> str:
    return urlparse(url or "").netloc.removeprefix("www.")


def _write_summary(summary: dict, stamp: str) -> str:
    path = os.path.join(LOGS, "discovered", f"backfill-{stamp}.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    return path


def backfill_licenses(csv_path: str | None = None, *, only_blank: bool = True,
                      limit: int | None = None, client=None,
                      github_token: str | None = None, dry_run: bool = False,
                      then_blacklist: bool = True, log_every: int = 25) -> dict:
    """Detect + write licenses for existing catalog rows; optionally blacklist reds.

    ``only_blank`` (default) detects only rows with a blank/Unknown License; set it
    False to re-detect every row. ``limit`` caps how many rows are *detected* (for a
    quick sample). ``github_token`` (or ``$GITHUB_TOKEN``) lifts the GitHub API
    rate limit. With ``dry_run`` neither the catalog nor the blacklist is written -
    the summary still reports what *would* change.

    Returns ``{"scanned", "detected", "still_unknown", "blacklisted", "csv",
    "summary", "by_host", "dry_run"}``.
    """
    csv_path = csv_path or DEFAULT_CATALOG
    token = github_token or os.getenv("GITHUB_TOKEN") or None
    if not os.path.exists(csv_path):
        logger.info(f"source: backfill: no catalog at {csv_path}")
        return {"scanned": 0, "detected": 0, "still_unknown": 0, "blacklisted": 0,
                "csv": csv_path, "summary": None, "by_host": {}, "dry_run": dry_run}

    import pandas as pd

    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False, encoding="utf-8")
    if "License" not in df.columns:
        df["License"] = ""
    link_col = _link_column(df.columns)
    if link_col is None:
        logger.info("source: backfill: catalog has no link column; nothing to do")
        return {"scanned": 0, "detected": 0, "still_unknown": 0, "blacklisted": 0,
                "csv": csv_path, "summary": None, "by_host": {}, "dry_run": dry_run}

    targets = [i for i in df.index
               if (not only_blank) or _needs_detection(df.at[i, "License"])]
    if limit is not None:
        targets = targets[:limit]

    logger.info(f"source: backfill: detecting licenses for {len(targets)} of "
                f"{len(df)} rows (only_blank={only_blank}, dry_run={dry_run})")

    detected = 0
    still_unknown = 0
    by_host: dict[str, dict[str, int]] = {}
    for n, i in enumerate(targets, 1):
        url = str(df.at[i, link_col] or "").strip()
        host = _host(url)
        bucket = by_host.setdefault(host, {"scanned": 0, "found": 0})
        bucket["scanned"] += 1
        lic = detect_license(url, client=client, github_token=token)
        if lic:
            df.at[i, "License"] = lic
            detected += 1
            bucket["found"] += 1
        else:
            still_unknown += 1
        if n % log_every == 0 or n == len(targets):
            logger.info(f"source: backfill: {n}/{len(targets)} scanned, "
                        f"{detected} detected")

    if detected and not dry_run:
        os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
        tmp = f"{csv_path}.tmp"
        df.to_csv(tmp, index=False, encoding="utf-8")
        os.replace(tmp, csv_path)
        logger.info(f"source: backfill: wrote {detected} licenses -> {csv_path}")

    black = {"moved": 0, "rows": []}
    if then_blacklist:
        if dry_run:
            # Nothing was written, so preview from the in-memory (detected) catalog
            # rather than re-reading the unchanged file.
            _, _, report = blacklist.flagged_rows(df.to_dict("records"))
            black = {"moved": len(report), "rows": report}
        else:
            black = blacklist.move_flagged(csv_path, dry_run=False)
        logger.info(f"source: backfill: blacklisted {black['moved']} confirmed-red "
                    f"source(s){' (dry-run)' if dry_run else ''}")

    stamp = f"{date.today():%Y%m%d}"
    summary = {"scanned": len(targets), "detected": detected,
               "still_unknown": still_unknown, "blacklisted": black["moved"],
               "csv": csv_path, "dry_run": dry_run,
               "by_host": by_host, "blacklist_rows": black["rows"]}
    summary_path = _write_summary(summary, stamp)
    summary["summary"] = summary_path
    return summary
