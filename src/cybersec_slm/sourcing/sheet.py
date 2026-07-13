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
from urllib.parse import urlparse

from ..ingestion.sources import CATALOG_COLUMNS

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


def delete_rows(csv_path: str, *, links: list[str] | None = None,
                subdomains: list[str] | None = None) -> int:
    """Delete catalog rows by link and/or Sub-Domain; return the count removed.

    A row is removed if its (normalized) link is in ``links`` **or** its Sub-Domain
    is in ``subdomains``. Matching links use :func:`normalize_url` so a slightly
    different form of the same URL still matches. The write is atomic (temp file +
    ``os.replace``), so a crash never leaves a half-written catalog.
    """
    if not os.path.exists(csv_path) or not (links or subdomains):
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

    removed = int(mask.sum())
    if removed:
        remaining = df[~mask]
        os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
        tmp = f"{csv_path}.tmp"
        remaining.to_csv(tmp, index=False, encoding="utf-8")
        os.replace(tmp, csv_path)
    return removed


def append_rows(csv_path: str, rows: list[dict[str, str]]) -> int:
    """Append ``rows`` (column->value dicts) to the catalog CSV; return count.

    Rows are reindexed to the existing file's header (or :data:`CATALOG_COLUMNS`
    when the file is new), so unknown columns stay blank and column order is
    preserved. The write is atomic (temp file + ``os.replace``) so a crash never
    leaves a half-written catalog.
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

    new = pd.DataFrame(rows).reindex(columns=columns, fill_value="")
    combined = pd.concat([existing, new], ignore_index=True)

    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    tmp = f"{csv_path}.tmp"
    combined.to_csv(tmp, index=False, encoding="utf-8")
    os.replace(tmp, csv_path)
    return len(rows)
