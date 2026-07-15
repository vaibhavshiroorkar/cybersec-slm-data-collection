#!/usr/bin/env python3
"""Move sources with a confirmed-red license out of the catalog to a blacklist.

A source whose ``License`` is positively recognised as **red** (copyleft /
non-commercial / share-alike / proprietary / all-rights-reserved) can never be
used to train commercially, so it does not belong in ``sources/Sources.csv``.
:func:`move_flagged` relocates those rows to ``sources/Blacklist.csv`` (same
schema plus a ``Blacklist Reason`` column) and deletes them from the catalog.

"Confirmed red" is exactly ``license_gate.license_verdict(...) == "blocked"`` - a
blank / unrecognised / "Unknown" license is **never** blacklisted (it stays in
the catalog for a human or a later backfill). Reuses the atomic catalog I/O in
:mod:`sourcing.sheet`, so a crash never leaves a half-written file, and the move
is idempotent (a re-run finds nothing left to move).
"""

from __future__ import annotations

import os

from ..ingestion.license_gate import classify_license, license_verdict
from ..ingestion.sources import CATALOG_COLUMNS
from . import sheet

# The blacklist mirrors the catalog schema and adds one column for the reason.
BLACKLIST_COLUMNS: tuple[str, ...] = (*CATALOG_COLUMNS, "Blacklist Reason")


def blacklist_path(csv_path: str) -> str:
    """The Blacklist.csv that sits next to a given catalog CSV."""
    return os.path.join(os.path.dirname(csv_path) or ".", "Blacklist.csv")


def _link_of(row: dict) -> str:
    for k, v in row.items():
        if str(k).strip().lower() in ("dataset link", "url", "link",
                                       "dataset_link", "source url"):
            return str(v or "")
    return ""


def _append_blacklist(path: str, rows: list[dict]) -> None:
    """Append rows to Blacklist.csv, aligned to its header (create if absent)."""
    import pandas as pd

    if os.path.exists(path):
        existing = pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8")
        columns = list(existing.columns)
        for c in BLACKLIST_COLUMNS:
            if c not in columns:
                columns.append(c)
    else:
        existing = pd.DataFrame(columns=list(BLACKLIST_COLUMNS))
        columns = list(BLACKLIST_COLUMNS)

    new = pd.DataFrame(rows).reindex(columns=columns, fill_value="")
    combined = pd.concat([existing, new], ignore_index=True)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp"
    combined.to_csv(tmp, index=False, encoding="utf-8")
    os.replace(tmp, path)


def flagged_rows(records: list[dict]) -> tuple[list[dict], list[str], list[dict]]:
    """Classify catalog rows; return ``(flagged_records, links, report)``.

    A record is flagged when its License is a *confirmed-red* one
    (``license_verdict == "blocked"``) **and** it carries a link (deletion keys on
    the link, so a link-less row is left in place rather than duplicated). Each
    flagged record gets a ``Blacklist Reason``. Works on plain dict rows, so both
    :func:`move_flagged` (from a file) and a dry-run preview (from an in-memory
    catalog) share one code path.
    """
    flagged: list[dict] = []
    links: list[str] = []
    for row in records:
        if license_verdict(row.get("License")) != "blocked":
            continue
        link = _link_of(row)
        if not link:
            continue
        _, reason = classify_license(row.get("License"))
        record = dict(row)
        record["Blacklist Reason"] = reason
        flagged.append(record)
        links.append(link)
    report = [{"name": r.get("Name", ""), "link": _link_of(r),
               "license": r.get("License", ""), "reason": r.get("Blacklist Reason", "")}
              for r in flagged]
    return flagged, links, report


def move_flagged(csv_path: str, *, dry_run: bool = False) -> dict:
    """Move confirmed-red rows from ``csv_path`` to its Blacklist.csv.

    Returns ``{"moved": n, "rows": [{"name", "link", "license", "reason"}, ...]}``.
    With ``dry_run`` the flagged rows are only reported (neither file is written).
    """
    if not os.path.exists(csv_path):
        return {"moved": 0, "rows": []}
    import pandas as pd

    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False, encoding="utf-8")
    if df.empty or "License" not in df.columns:
        return {"moved": 0, "rows": []}

    flagged, flagged_links, report = flagged_rows(df.to_dict("records"))

    if flagged and not dry_run:
        _append_blacklist(blacklist_path(csv_path), flagged)
        sheet.delete_rows(csv_path, links=[link for link in flagged_links if link])

    return {"moved": len(flagged), "rows": report}
