#!/usr/bin/env python3
"""CSV-driven source catalog (offline / local file).

Reads a local CSV describing what to fetch and maps each row to a *source
descriptor* — the same shape the fetch/scrape handlers already consume. This is
the single source catalog: the corpus is curated entirely in one spreadsheet
(``sources/Sources.csv``; see the column convention below).

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

Row -> kind dispatch also covers two infrastructure sources by URL:
    services.nvd.nist.gov/...  -> api   (NVD CVE 2.0 paginated API)
    *.xml.zip / cwe.mitre.org  -> xml   (MITRE CWE XML-in-ZIP)

Public API:
    load_descriptors(spec) -> list[dict]
"""

from __future__ import annotations

import os
import re
from urllib.parse import urlparse

from .common import GOV_US, logger

# The catalog lives in the repo's ``sources/`` dir (curated, version-controlled),
# not the relocatable data root — resolve it relative to this package, like
# allowlist.py does for allowlist.yaml.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
DEFAULT_CATALOG = os.path.join(_PKG_ROOT, "sources", "Sources.csv")

# Canonical catalog schema — the columns of ``sources/Sources.csv`` (in order).
# Shared by the sourcing crawler (which appends rows) and the cleaning driver
# (which writes the Cleaned* columns back), so the column list lives in one place.
CATALOG_COLUMNS: tuple[str, ...] = (
    "Name", "Sub-Domain", "Description", "Dataset Link", "File Count",
    "Category", "Original Format", "Original Size (MB)", "JSONL Size (MB)",
    "Total Lines", "Cleaned Size (MB)", "Cleaned Lines", "License",
    "Last Updated", "Uploaded?", "Cleaned?", "Verified?", "Date Added", "Note",
)

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


# Cap slug length so data/clean/<domain>/<slug>/<slug>.jsonl stays under the
# Windows 260-char MAX_PATH (long paper-title slugs otherwise break tools that
# read the file, e.g. Google Drive upload/sync).
SLUG_MAXLEN = 45


def slugify(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return (s[:SLUG_MAXLEN].rstrip("-") or "source")


def _resolve(spec: str) -> str:
    """Validate and return a local path for the catalog CSV (offline only)."""
    if not os.path.exists(spec):
        raise FileNotFoundError(f"sources catalog not found: {spec}")
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
        if "services.nvd.nist.gov" in low:
            kind = "api"          # NVD CVE 2.0 — paginated REST API (fetch_nvd)
        elif low.endswith(".xml.zip") or ("cwe.mitre.org" in low and ".xml" in low):
            kind = "xml"          # MITRE CWE — XML-in-ZIP needing custom parsing (scrape_cwe)
        elif "huggingface.co/datasets/" in low:
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
    if kind == "api":
        return dict(kind="api", domain=domain, slug=slug, title=name,
                    license=lic or GOV_US, url=url)
    if kind == "xml":
        return dict(kind="xml", domain=domain, slug=slug, title=name,
                    license=lic, url=url)
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


def load_descriptors(spec: str) -> list[dict]:
    """Read the catalog CSV at ``spec`` into a list of source descriptors."""
    import pandas as pd

    path = _resolve(spec)
    # dtype=str + keep_default_na=False: every cell stays a string and blanks
    # stay "" (never NaN), so descriptor mapping sees clean text values.
    df = pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8")
    df = _norm_headers(df)
    out: list[dict] = []
    for row in df.to_dict("records"):
        d = _row_to_descriptor(row)
        if d is not None:
            out.append(d)
    logger.info(f"loaded {len(out)} sources from {os.path.basename(path)}")
    return out
