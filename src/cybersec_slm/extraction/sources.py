#!/usr/bin/env python3
"""Spreadsheet-driven source catalog.

Reads an Excel workbook (local path or http(s) link) describing what to fetch
and maps each row to a *source descriptor* — the same shape the fetch/scrape
handlers already consume. This lets the corpus be curated in a spreadsheet
(see ``sources/source_registry.csv`` for the column convention) instead of
editing :mod:`cybersec_slm.extraction.manifest`.

Expected columns (header matching is case-insensitive; extras are ignored):
    source_name, url, category, format, access_method, license
Optional columns refine the mapping:
    kind, ref, domain (or sub_domain), json_key, use_js, max_pages, allow_prefix,
    description, title, slug

Row -> kind dispatch (when ``kind`` is not given explicitly):
    huggingface.co/datasets/<o>/<n>      -> hf
    kaggle.com/datasets/<o>/<n>          -> kaggle
    format == PDF  (or url ends .pdf)    -> pdf
    format == HTML or access == scraping -> website
    format == JSON + api/bulk_download   -> feed   (needs/guesses json_key)
    github.com / raw.githubusercontent   -> github
    anything else with a direct file URL -> url

Public API:
    load_descriptors(spec, sheet=None) -> list[dict]
    load_sources(spec, sheet=None)     -> (datasets, pdfs, feeds, sites) tuples
"""

from __future__ import annotations

import os
import re
from urllib.parse import urlparse

from . import common
from .common import GOV_US, logger

# Coarse spreadsheet categories -> the sub-domain folder names used elsewhere.
CATEGORY_TO_DOMAIN = {
    "articles_news_blogs": "Threat Intelligence",
    "vulnerabilities": "Threat Intelligence",
    "malware": "Malware Analysis",
    "network": "Network Security",
    "application": "Application Security",
    "cloud": "Cloud Security",
    "iam": "Identity Access and Management",
    "incident_response": "Incident Response and Forensics",
    "forensics": "Incident Response and Forensics",
    "privacy": "Data Security and Privacy",
    "pentest": "Penetration Testing and Vulnerability Management",
    "grc": "Governance, Risk and Compliance",
    "crypto": "Cryptography",
    "secops": "Security Operations",
}

# Default JSON key to read records from, by feed slug hint.
_FEED_KEY_GUESSES = ("vulnerabilities", "objects", "data", "results", "items")


# Cap slug length so clean_data/<domain>/<slug>/<slug>.jsonl stays under the
# Windows 260-char MAX_PATH (long paper-title slugs otherwise break tools that
# read the file, e.g. Google Drive upload/sync).
SLUG_MAXLEN = 45


def slugify(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return (s[:SLUG_MAXLEN].rstrip("-") or "source")


_GSHEET_RE = re.compile(r"docs\.google\.com/spreadsheets/d/([A-Za-z0-9_-]+)")


def _normalize_gsheet(spec: str) -> str:
    """Rewrite a Google Sheets share/edit URL to its .xlsx export endpoint.

    An ``/edit#gid=0`` link serves HTML, not a workbook, so it must be turned
    into ``/export?format=xlsx`` (which exports the whole workbook — the first
    sheet is read by default; use ``--sheet`` to pick another). The sheet must
    be shared as "Anyone with the link -> Viewer" for an unauthenticated export.
    """
    m = _GSHEET_RE.search(spec)
    if not m:
        return spec
    return (f"https://docs.google.com/spreadsheets/d/{m.group(1)}"
            "/export?format=xlsx")


def _check_xlsx(path: str) -> None:
    with open(path, "rb") as f:
        sig = f.read(2)
    if sig != b"PK":          # every .xlsx is a zip; zips start with "PK"
        raise ValueError(
            f"{path} is not a valid .xlsx (got {sig!r}). If this is a Google "
            "Sheet, share it as 'Anyone with the link -> Viewer' so it can be "
            "exported without signing in.")


def _resolve(spec: str) -> str:
    """Return a local path for ``spec``; download first if it is an http(s) URL."""
    if spec.lower().startswith(("http://", "https://")):
        url = _normalize_gsheet(spec)
        dest_dir = os.path.join(common.LOGS, "_sources")
        os.makedirs(dest_dir, exist_ok=True)
        name = os.path.basename(urlparse(url).path)
        if not name.lower().endswith((".xlsx", ".xls", ".csv")):
            name = "sources.xlsx"
        dest = os.path.join(dest_dir, name)
        logger.info(f"downloading sources sheet: {url}")
        common.download(url, dest)
        _check_xlsx(dest)
        return dest
    return spec


def _norm_headers(df):
    df.columns = [re.sub(r"[ \-]+", "_", str(c).strip().lower()) for c in df.columns]
    return df


def _val(row: dict, *names, default=None):
    """First non-empty value among the given column names."""
    for n in names:
        v = row.get(n)
        if v is None:
            continue
        s = str(v).strip()
        if s and s.lower() != "nan":
            return s
    return default


def _bool(v, default=False) -> bool:
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "y", "js", "on")


def _int(v, default: int) -> int:
    """Parse an int from a spreadsheet cell, tolerating floats ('70.0') / junk."""
    try:
        return int(float(str(v).strip()))
    except (TypeError, ValueError):
        return default


def _domain_for(row: dict) -> str:
    explicit = _val(row, "domain", "sub_domain", "subdomain")
    if explicit:
        return explicit
    cat = (_val(row, "category", default="") or "").lower()
    return CATEGORY_TO_DOMAIN.get(cat, _val(row, "category", default="Uncategorized"))


def _feed_key(slug: str, row: dict) -> str:
    explicit = _val(row, "json_key", "record_key")
    if explicit:
        return explicit
    for guess in _FEED_KEY_GUESSES:
        if guess in slug.lower():
            return guess
    return "vulnerabilities" if "kev" in slug.lower() else "data"


def _row_to_descriptor(row: dict) -> dict | None:
    url = _val(row, "url", "dataset_link", "link", "source_url", default="")
    name = _val(row, "source_name", "name", "title", default=url) or url
    if not url and not _val(row, "ref"):
        logger.warning(f"skipping source row with no url/ref: {name!r}")
        return None
    fmt = (_val(row, "format", "original_format", "file_format",
                default="") or "").lower()
    access = (_val(row, "access_method", "access", default="") or "").lower()
    lic = _val(row, "license", default="to-verify")
    domain = _domain_for(row)
    desc = _val(row, "description", "notes", default=name)
    slug = _val(row, "slug", default=slugify(name))
    slug = (slug[:SLUG_MAXLEN].rstrip("-_") or "source")   # bound path length
    low = url.lower()

    kind = _val(row, "kind")
    if not kind:
        if "huggingface.co/datasets/" in low:
            kind = "hf"
        elif "kaggle.com/datasets/" in low:
            kind = "kaggle"
        elif fmt == "pdf" or low.endswith(".pdf") or "arxiv.org/pdf/" in low:
            kind = "pdf"          # arxiv /pdf/<id> serves a PDF with no .pdf suffix
        elif (fmt == "html" or access == "scraping"
              or "archive.ics.uci.edu/dataset/" in low):
            kind = "website"      # a UCI /dataset/ link is an HTML landing page, not data
        elif (fmt == "json" or low.endswith(".json")) and "github" not in low:
            kind = "feed"          # a bare .json endpoint is a record collection
        elif "github.com" in low or "raw.githubusercontent.com" in low:
            kind = "github"
        else:
            kind = "url"

    if kind in ("hf", "kaggle"):
        ref = _val(row, "ref")
        if not ref:
            m = re.search(r"/datasets/([^/]+/[^/?#]+)", url)
            ref = m.group(1) if m else slug
        return dict(kind=kind, ref=ref, domain=domain, description=desc,
                    license=lic, url=url)
    if kind in ("url", "github"):
        ref = _val(row, "ref", default=slug)
        return dict(kind=kind, ref=ref, domain=domain, description=desc,
                    license=lic, url=url)
    if kind == "pdf":
        return dict(kind="pdf", domain=domain, slug=slug, title=name,
                    license=lic or GOV_US, url=url)
    if kind == "feed":
        return dict(kind="feed", domain=domain, slug=slug, title=name,
                    license=lic, url=url, json_key=_feed_key(slug, row))
    if kind == "website":
        prefix = _val(row, "allow_prefix")
        if not prefix:
            p = urlparse(url)
            prefix = f"{p.scheme}://{p.netloc}{p.path.rsplit('/', 1)[0]}/"
        return dict(kind="website", domain=domain, slug=slug, start_url=url,
                    license=lic, use_js=_bool(_val(row, "use_js")),
                    max_pages=_int(_val(row, "max_pages", default="70"), 70),
                    allow_prefix=prefix, description=desc)
    logger.warning(f"unknown kind {kind!r} for source {name!r}; skipping")
    return None


def load_descriptors(spec: str, sheet: str | int | None = None) -> list[dict]:
    """Read the spreadsheet at ``spec`` into a list of source descriptors."""
    import pandas as pd

    path = _resolve(spec)
    df = pd.read_excel(path, sheet_name=0 if sheet is None else sheet)
    df = _norm_headers(df)
    out: list[dict] = []
    for row in df.to_dict("records"):
        d = _row_to_descriptor(row)
        if d is not None:
            out.append(d)
    logger.info(f"loaded {len(out)} sources from {os.path.basename(path)}")
    return out


# --------------------------------------------------- legacy tuple adapters ---
def descriptor_to_tuple(d: dict):
    """Convert a descriptor back to the positional tuple a handler expects."""
    k = d["kind"]
    if k in ("hf", "kaggle"):
        return (k, d["ref"], d["domain"], d["description"], d["license"])
    if k in ("url", "github"):
        return (k, d["ref"], d["domain"], d["description"], d["license"], d["url"])
    if k == "pdf":
        return (d["domain"], d["slug"], d["title"], d["license"], d["url"])
    if k == "feed":
        return (d["domain"], d["slug"], d["title"], d["license"], d["url"],
                d["json_key"])
    if k == "website":
        return (d["domain"], d["slug"], d["start_url"], d["license"], d["use_js"],
                d["max_pages"], d["allow_prefix"], d["description"])
    raise ValueError(f"unknown kind: {k}")


def load_sources(spec: str, sheet: str | int | None = None):
    """Return ``(datasets, pdfs, feeds, sites)`` tuple-lists (sequential path)."""
    datasets, pdfs, feeds, sites = [], [], [], []
    bucket = {"hf": datasets, "kaggle": datasets, "url": datasets,
              "github": datasets, "pdf": pdfs, "feed": feeds, "website": sites}
    for d in load_descriptors(spec, sheet):
        bucket[d["kind"]].append(descriptor_to_tuple(d))
    return datasets, pdfs, feeds, sites


# ----------------------------------------------- manifest.py tuple adapters --
def _dataset_to_descriptor(t) -> dict:
    kind, ref, domain, desc, lic = t[:5]
    d = dict(kind=kind, ref=ref, domain=domain, description=desc, license=lic)
    if kind in ("url", "github"):
        d["url"] = t[5]
    elif kind == "hf":
        d["url"] = f"https://huggingface.co/datasets/{ref}"
    else:
        d["url"] = f"https://www.kaggle.com/datasets/{ref}"
    return d


def descriptors_from_lists(datasets, pdfs, feeds, sites) -> list[dict]:
    """Convert the four manifest-style tuple-lists into source descriptors."""
    out = [_dataset_to_descriptor(t) for t in datasets]
    out += [dict(kind="pdf", domain=t[0], slug=t[1], title=t[2], license=t[3],
                 url=t[4]) for t in pdfs]
    out += [dict(kind="feed", domain=t[0], slug=t[1], title=t[2], license=t[3],
                 url=t[4], json_key=t[5]) for t in feeds]
    out += [dict(kind="website", domain=t[0], slug=t[1], start_url=t[2],
                 license=t[3], use_js=t[4], max_pages=t[5], allow_prefix=t[6],
                 description=t[7]) for t in sites]
    return out


def manifest_descriptors() -> list[dict]:
    """Descriptors for the built-in catalog (used when no --sources is given)."""
    from .manifest import DATASETS, FEEDS, PDFS, SITES
    return descriptors_from_lists(DATASETS, PDFS, FEEDS, SITES)
