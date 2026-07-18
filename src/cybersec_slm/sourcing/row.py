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

# "Field" is the broad subject the profile covers, one level above Sub-Domain.
# Derived from the active profile's domain name, with a title-cased fallback so a
# new domain gets a sensible label without a code change.
_FIELD_BY_DOMAIN = {
    "BANKING_COMPLIANCE": "Finance",
    "CYBERSEC": "Cybersecurity",
}

# Signals that a source is Indian rather than global. A ``.in`` host is the strong
# one; the rest catch Indian regulators/institutions on ``.gov``/``.org`` hosts and
# in the row text.
_INDIA_HINTS = (
    "india", "indian", "reserve bank of india", "rbi", "sebi", "irdai", "npci",
    "union bank", "unionbank", "nseindia", "bseindia", "mca.gov", "incometax",
    "gst", "godl", "data.gov.in",
)


def field_label() -> str:
    """The broad ``Field`` for the active profile (e.g. Finance, Cybersecurity)."""
    try:
        from .catalog import domain_name
        dn = (domain_name() or "").strip()
    except Exception:
        return _BLANK
    if not dn:
        return _BLANK
    return _FIELD_BY_DOMAIN.get(dn, dn.replace("_", " ").title())


def country_for(link: str, text: str = "") -> str:
    """Classify a source as ``India`` or ``Global`` from its host and row text."""
    host = urlparse(link or "").netloc.lower().removeprefix("www.")
    if host.endswith(".in"):
        return "India"
    blob = f"{host} {text}".lower()
    if any(hint in blob for hint in _INDIA_HINTS):
        return "India"
    return "Global"


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
    row["Field"] = field_label()
    row["Country"] = country_for(result.link, f"{result.title} {result.snippet}")
    row["Description"] = result.snippet[:300]
    row["Dataset Link"] = result.link
    row["Category"] = category
    row["Original Format"] = fmt
    row["Date Added"] = added
    return row


# Sheet values the Category / Original Format columns take, matching what
# :func:`~.classify.infer_category_and_format` writes for a discovered source, so
# a hand-added row is indistinguishable from a crawled one.
CATEGORIES: tuple[str, ...] = ("Dataset", "Repository", "Document", "Website", "Feed", "API")
FORMATS: tuple[str, ...] = ("JSONL", "JSON", "CSV", "PARQUET", "XLSX", "TXT",
                            "PDF", "XML", "HTML", "RSS", "ATOM")


def build_manual_row(*, name: str, subdomain: str, link: str,
                     description: str = "", category: str = "",
                     original_format: str = "", license: str = "",
                     is_synthetic: bool = False,
                     extra: dict[str, str] | None = None,
                     today: str | None = None) -> dict[str, str]:
    """Build one catalog row for a source added by hand (the dashboard's form).

    Mirrors :func:`build_row` — same columns, same ``Date Added`` format — but
    takes the fields from a human instead of a search result, and infers
    ``Category`` / ``Original Format`` from the link when they are left blank, so
    a hand-added row lands in the catalog identical in shape to a discovered one.
    ``extra`` fills any other catalog column (sizes, line counts, Author, Tags,
    Note); unknown keys are ignored so a caller cannot widen the schema.

    Raises ``ValueError`` when a required field (name / sub-domain / link) is blank.
    """
    name, subdomain, link = name.strip(), subdomain.strip(), link.strip()
    missing = [label for label, val in (("Name", name), ("Sub-Domain", subdomain),
                                        ("Dataset Link", link)) if not val]
    if missing:
        raise ValueError(f"missing required field(s): {', '.join(missing)}")

    inferred_cat, inferred_fmt = infer_category_and_format(link)
    row = {c: _BLANK for c in SHEET_COLUMNS}
    row["Name"] = name
    row["Sub-Domain"] = subdomain
    row["Description"] = description.strip()
    row["Dataset Link"] = link
    row["Category"] = category.strip() or inferred_cat
    row["Original Format"] = original_format.strip() or inferred_fmt
    row["Field"] = field_label()
    row["Country"] = country_for(link, f"{name} {description}")
    row["License"] = license.strip()
    row["Is Synthetic?"] = "Yes" if is_synthetic else _BLANK
    row["Date Added"] = today or date.today().strftime("%d/%m/%Y")
    for col, val in (extra or {}).items():
        if col in row and str(val).strip():
            row[col] = str(val).strip()
    return row


def row_to_list(row: dict[str, str]) -> list[str]:
    """Flatten a row dict to a values list in :data:`SHEET_COLUMNS` order."""
    return [row.get(c, _BLANK) for c in SHEET_COLUMNS]
