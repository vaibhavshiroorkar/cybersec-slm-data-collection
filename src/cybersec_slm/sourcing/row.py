#!/usr/bin/env python3
"""Map a search :class:`~.search.Result` into a catalog (Sources.csv) row.

The catalog's columns (exact order) are the contract between this crawler and the
``sources/Sources.csv`` catalog. Only the fields that are knowable at *sourcing*
time are filled; the rest (counts, sizes, cleaned/verification status) are left
blank for the ingestion/cleaning stages and a human to complete.
"""

from __future__ import annotations

import re
from datetime import date
from urllib.parse import urlparse

from ..ingestion.sources import CATALOG_COLUMNS
from .classify import infer_category_and_format, refine_domain
from .search import Result

# The catalog columns, in order (single source of truth lives in ingestion.sources).
SHEET_COLUMNS: tuple[str, ...] = CATALOG_COLUMNS

# Fields the crawler fills vs. leaves for ingestion/humans.
_BLANK = ""


def _derive_name(result: Result) -> str:
    """A short, sheet-friendly name — the org/owner for HF & GitHub, else title."""
    link = result.link
    m = re.search(r"huggingface\.co/datasets/([^/]+)/", link, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"(?:github\.com|gitlab\.com)/([^/]+)/", link, re.IGNORECASE)
    if m and m.group(1).lower() not in ("orgs", "search", "topics"):
        return m.group(1)
    # Otherwise: the title up to the first separator, or the host.
    title = re.split(r"\s[|\-–·:]\s", result.title.strip())[0].strip()
    if title:
        return title[:80]
    return (result.display_link or urlparse(result.link).netloc).removeprefix("www.")


def build_row(result: Result, default_domain: str, *,
              today: str | None = None,
              domain_vocab: dict[str, set[str]] | None = None) -> dict[str, str]:
    """Build one sheet row (a column->value dict) from a search result.

    ``domain_vocab`` is the tie-break vocabulary for :func:`refine_domain`
    (from :func:`~.classify.build_domain_vocab`); pass it in once per discovery
    run rather than per row/result.
    """
    domain = refine_domain(default_domain, result.title, result.snippet, domain_vocab)
    category, fmt = infer_category_and_format(result.link)
    added = today or date.today().strftime("%d/%m/%Y")

    row = {c: _BLANK for c in SHEET_COLUMNS}
    row["Name"] = _derive_name(result)
    row["Sub-Domain"] = domain
    row["Description"] = result.snippet[:300]
    row["Dataset Link"] = result.link
    row["Category"] = category
    row["Original Format"] = fmt
    row["Date Added"] = added
    return row


def row_to_list(row: dict[str, str]) -> list[str]:
    """Flatten a row dict to a values list in :data:`SHEET_COLUMNS` order."""
    return [row.get(c, _BLANK) for c in SHEET_COLUMNS]
