#!/usr/bin/env python3
"""Local catalog (Sources.csv) I/O for sourcing: read existing links + append rows.

The catalog is a single local CSV (``sources/Sources.csv``) — no network, no
Google auth. ``existing_links`` reads it to dedup discovered candidates, and
``append_rows`` adds the survivors. New rows are aligned to the *live* file's
header (falling back to the canonical schema when creating the file), so the
ingestion/cleaning columns (Cleaned?, sizes, ...) are preserved and never
shifted.

URL normalization (:func:`normalize_url`) is what makes "already exists" robust:
scheme, ``www.``, trailing slashes, query strings and fragments are stripped so
the same dataset linked two slightly different ways is still recognized as one.
"""

from __future__ import annotations

import os
import time
from urllib.parse import urlparse

from ..ingestion.sources import CATALOG_COLUMNS


def _atomic_replace(src: str, dst: str, retries: int = 5, delay: float = 1.0) -> None:
    """Safely replace dst with src, retrying on Windows PermissionError locks."""
    for attempt in range(retries):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                raise


# Header names (lowercased) that may hold a source link, in preference order.
_LINK_HEADERS = ("dataset link", "url", "link", "dataset_link", "source url")


def normalize_url(url: str) -> str:
    """Canonical form used for dedup comparisons (not for storage)."""
    s = (url or "").strip().lower()
    if not s:
        return ""
    p = urlparse(s if "://" in s else "//" + s, scheme="https")
    host = p.netloc.removeprefix("www.")
    path = p.path.rstrip("/")
    return f"{host}{path}"


def _link_column(columns) -> str | None:
    """The first column whose (lowercased) name is a known link header."""
    lower = {str(c).strip().lower(): c for c in columns}
    for h in _LINK_HEADERS:
        if h in lower:
            return lower[h]
    return None


def existing_links(csv_path: str) -> set[str]:
    """Normalized set of links already in the catalog CSV (empty if it's absent)."""
    if not csv_path or not os.path.exists(csv_path):
        return set()
    import pandas as pd

    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False, encoding="utf-8")
    col = _link_column(df.columns)
    if col is None:
        return set()
    return {n for n in (normalize_url(v) for v in df[col]) if n}


def _subdomain_column(columns) -> str | None:
    lower = {str(c).strip().lower(): c for c in columns}
    for h in ("sub-domain", "subdomain", "sub domain", "sub_domain"):
        if h in lower:
            return lower[h]
    return None


def valid_counts_by_subdomain(csv_path: str) -> dict[str, int]:
    """Count existing **commercial-valid** rows per Sub-Domain in the catalog.

    A row counts only when its License passes the ingestion gate as clearly
    commercial (``license_verdict == "ok"``); blank/unknown and confirmed-red
    rows are excluded. Used by the valid-gated fill to compute each domain's
    deficit to its target. Returns ``{}`` for a missing/empty/columnless catalog.
    """
    if not csv_path or not os.path.exists(csv_path):
        return {}
    import pandas as pd

    from ..ingestion.license_gate import license_verdict

    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False, encoding="utf-8")
    sdcol = _subdomain_column(df.columns)
    if sdcol is None or "License" not in df.columns:
        return {}
    counts: dict[str, int] = {}
    for sub, lic in zip(df[sdcol], df["License"], strict=True):
        if license_verdict(lic) == "ok":
            key = str(sub).strip()
            counts[key] = counts.get(key, 0) + 1
    return counts


def rename_subdomain(csv_path: str, old: str, new: str) -> int:
    """Relabel every catalog row whose Sub-Domain is ``old`` to ``new``; return the
    count.

    Renaming a sub-domain in ``sources/keywords.yaml`` (the taxonomy) leaves the
    rows in ``Sources.csv`` still carrying the old label, which would strand them
    outside the taxonomy — they would no longer match any configured sub-domain
    for a selective run, and the schema stage would not resolve their enum code.
    This relabels them in the same edit. Matching is exact after stripping
    surrounding whitespace. The write is atomic (temp file + ``os.replace``).
    """
    old, new = (old or "").strip(), (new or "").strip()
    if not old or not new or old == new or not os.path.exists(csv_path):
        return 0
    import pandas as pd

    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False, encoding="utf-8")
    if df.empty:
        return 0
    sdcol = _subdomain_column(df.columns)
    if sdcol is None:
        return 0

    mask = df[sdcol].map(lambda v: str(v).strip() == old)
    changed = int(mask.sum())
    if changed:
        df.loc[mask, sdcol] = new
        os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
        tmp = f"{csv_path}.tmp"
        df.to_csv(tmp, index=False, encoding="utf-8")
        _atomic_replace(tmp, csv_path)
    return changed


def delete_rows(csv_path: str, *, links: list[str] | None = None,
                subdomains: list[str] | None = None,
                positions: list[int] | None = None) -> int:
    """Delete catalog rows by link, Sub-Domain, and/or position; return the count.

    A row is removed if its (normalized) link is in ``links``, its Sub-Domain is in
    ``subdomains``, **or** its 1-based position (row order in the CSV, matching the
    Sources.csv table) is in ``positions``. Matching links use :func:`normalize_url`
    so a slightly different form of the same URL still matches; out-of-range
    positions are ignored. The write is atomic (temp file + ``os.replace``), so a
    crash never leaves a half-written catalog.
    """
    if not os.path.exists(csv_path) or not (links or subdomains or positions):
        return 0
    import pandas as pd

    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False, encoding="utf-8")
    if df.empty:
        return 0

    mask = pd.Series(False, index=df.index)
    if links:
        col = _link_column(df.columns)
        if col is not None:
            wanted = {n for n in (normalize_url(x) for x in links) if n}
            mask |= df[col].map(lambda v: normalize_url(v) in wanted)
    if subdomains:
        sdcol = _subdomain_column(df.columns)
        if sdcol is not None:
            wanted_sd = {str(s).strip() for s in subdomains}
            mask |= df[sdcol].map(lambda v: str(v).strip() in wanted_sd)
    if positions:
        wanted_idx = {p - 1 for p in positions if p >= 1}
        mask |= pd.Series(df.reset_index(drop=True).index.isin(wanted_idx),
                          index=df.index)

    removed = int(mask.sum())
    if removed:
        remaining = df[~mask]
        os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
        tmp = f"{csv_path}.tmp"
        remaining.to_csv(tmp, index=False, encoding="utf-8")
        _atomic_replace(tmp, csv_path)
    return removed


def append_rows(csv_path: str, rows: list[dict[str, str]]) -> int:
    """Append ``rows`` (column->value dicts) to the catalog CSV; return count.

    Rows are reindexed to the existing file's header (or :data:`CATALOG_COLUMNS`
    when the file is new). Any column carried by the new rows but missing from the
    existing header (e.g. enrichment's Author/Popularity/Tags on a catalog written
    before enrichment existed) is unioned in - appended at the end so existing
    column order is preserved, with existing rows left blank in it. The write is
    atomic (temp file + ``os.replace``) so a crash never leaves a half-written
    catalog.
    """
    if not rows:
        return 0
    import pandas as pd

    if os.path.exists(csv_path):
        existing = pd.read_csv(csv_path, dtype=str, keep_default_na=False,
                               encoding="utf-8")
        columns = list(existing.columns)
    else:
        existing = pd.DataFrame(columns=list(CATALOG_COLUMNS))
        columns = list(CATALOG_COLUMNS)

    # Union any new-row columns the existing header lacks, appended at the end.
    seen = set(columns)
    for r in rows:
        for c in r:
            if c not in seen and c in CATALOG_COLUMNS:
                seen.add(c)
                columns.append(c)

    new = pd.DataFrame(rows).reindex(columns=columns, fill_value="")
    combined = pd.concat([existing, new], ignore_index=True)

    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    tmp = f"{csv_path}.tmp"
    combined.to_csv(tmp, index=False, encoding="utf-8")
    _atomic_replace(tmp, csv_path)
    return len(rows)
