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

from . import rss as _rss
from .common import GOV_US, logger

# The catalog lives in the repo's ``sources/`` dir (curated, version-controlled),
# not the relocatable data root — resolve it relative to this package, like
# allowlist.py does for allowlist.yaml. Which catalog, though, depends on the
# active *profile* (cybersec / ubi / ...), so this is resolved per call rather
# than bound once at import — see cybersec_slm.sourcing.profiles.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


def default_catalog() -> str:
    """Path to the active profile's ``Sources.csv``."""
    # Imported lazily: sourcing.profiles -> sourcing.catalog -> this module.
    from ..sourcing import profiles
    return profiles.catalog_path()


def __getattr__(name: str):
    """Back-compat: ``sources.DEFAULT_CATALOG`` still resolves (now per-profile)."""
    if name == "DEFAULT_CATALOG":
        return default_catalog()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

# Canonical catalog schema — the columns of ``sources/Sources.csv`` (in order).
# Shared by the sourcing crawler (which appends rows) and the cleaning driver
# (which writes the Cleaned* columns back), so the column list lives in one place.
CATALOG_COLUMNS: tuple[str, ...] = (
    "Name", "Sub-Domain", "Field", "Country", "Description", "Dataset Link", "File Count",
    "Category", "Original Format", "Original Size (MB)", "JSONL Size (MB)",
    "Total Lines", "Cleaned Size (MB)", "Cleaned Lines", "License",
    "Last Updated", "Uploaded?", "Cleaned?", "Verified?", "Is Synthetic?",
    "Date Added", "Author", "Popularity", "Tags", "Note",
)

# Coarse spreadsheet categories -> a sub-domain name. Only consulted for a foreign
# CSV that carries a broad ``category`` column and no ``Sub-Domain`` (every row of
# the canonical catalog has one, so this is a fallback path).
#
# These are hints from the original cybersecurity taxonomy, and are honored ONLY
# when the name they map to is actually present in the live taxonomy
# (``sources/keywords.yaml``) - see :func:`_domain_for`. That keeps the mapping
# from hard-coding this pipeline to cybersecurity: point ``keywords.yaml`` at a
# different data domain and these hints simply stop matching, rather than filing
# rows under a sub-domain that domain never defined.
CATEGORY_TO_DOMAIN = {
    "articles_news_blogs": "Threat Intelligence",
    "vulnerabilities": "Vulnerability Management",
    "malware": "Threat Intelligence",
    "network": "Network Security",
    "application": "Application Security",
    "cloud": "Cloud Security",
    "iam": "Identity Access and Management",
    "incident_response": "Incident Response and Forensics",
    "forensics": "Incident Response and Forensics",
    "privacy": "Data Security and Privacy",
    "pentest": "Penetration Testing",
    "vuln_management": "Vulnerability Management",
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


def _size_hint(row: dict) -> float:
    """Best-effort byte-size proxy (in MB) for ordering sources smallest-first.

    Reads the catalog's ``Original Size (MB)`` (falling back to ``JSONL Size
    (MB)``). Rows with no usable size (newly discovered sources that haven't
    been measured yet) sort last (``inf``) so known-small, fast sources run
    first and the pipeline shows early progress instead of stalling on a
    multi-GB download.
    """
    for col in ("original_size_(mb)", "original_size_mb", "jsonl_size_(mb)",
                "jsonl_size_mb"):
        raw = _val(row, col)
        if raw is None:
            continue
        try:
            return float(str(raw).replace(",", "").strip())
        except (TypeError, ValueError):
            continue
    return float("inf")


def _taxonomy_key(s: str) -> str:
    """Normalize a name/code to a comparison key.

    ``"Network Security"`` and ``"network security"`` both key to
    ``network_security``, so a category cell matches however it is spelled.
    """
    return re.sub(r"[^a-z0-9]+", "_", str(s or "").strip().lower()).strip("_")


# Cache for the taxonomy lookup, keyed on the catalog file's (path, mtime) so an
# edit is picked up and a different data root never reads another's cache. Without
# it, every catalog row would re-read and re-parse keywords.yaml.
_taxonomy_cache: tuple[tuple[str, float], dict[str, str]] | None = None


def _taxonomy_lookup() -> dict[str, str]:
    """``{normalized key -> sub-domain name}`` for the live keyword taxonomy.

    Keys each configured sub-domain by both its name and its schema enum code, so
    a foreign CSV's ``category`` cell resolves whether it spells the sub-domain out
    (``"Network Security"``, ``"network security"``) or uses the code (``NETWORK``).
    Returns ``{}`` if the taxonomy cannot be read, which makes :func:`_domain_for`
    fall back to the row's own category text.
    """
    global _taxonomy_cache
    try:
        # Imported lazily: sourcing.sheet imports this module for CATALOG_COLUMNS,
        # so a module-level import here would be a cycle.
        from ..sourcing import catalog as _catalog
    except Exception:
        return {}
    try:
        path = _catalog.catalog_path()
        mtime = os.path.getmtime(path) if os.path.exists(path) else 0.0
    except OSError:
        path, mtime = "", 0.0
    key = (path, mtime)
    if _taxonomy_cache is not None and _taxonomy_cache[0] == key:
        return _taxonomy_cache[1]
    try:
        cat = _catalog.load()
    except Exception as ex:
        logger.warning(f"could not read the sub-domain taxonomy ({type(ex).__name__}); "
                       "falling back to the catalog's own category values")
        return {}
    lookup: dict[str, str] = {}
    for name, spec in cat.items():
        lookup.setdefault(_taxonomy_key(name), name)
        code = str((spec or {}).get("code") or "").strip()
        if code:
            lookup.setdefault(_taxonomy_key(code), name)
    _taxonomy_cache = (key, lookup)
    return lookup


def _domain_for(row: dict) -> str:
    """The Sub-Domain a catalog row belongs to.

    An explicit ``Sub-Domain`` column wins (every canonical catalog row has one).
    Otherwise the row's coarse ``category`` is resolved against the live taxonomy
    in ``sources/keywords.yaml`` — first directly (by sub-domain name or enum
    code), then through the legacy :data:`CATEGORY_TO_DOMAIN` hints, which apply
    only when the sub-domain they name is one this taxonomy actually defines.
    Unresolvable categories are kept verbatim so nothing is silently refiled.
    """
    explicit = _val(row, "domain", "sub_domain", "subdomain")
    if explicit:
        return explicit
    raw_cat = _val(row, "category", default="") or ""
    if not raw_cat.strip():
        return "Uncategorized"

    lookup = _taxonomy_lookup()
    direct = lookup.get(_taxonomy_key(raw_cat))
    if direct:
        return direct
    hinted = CATEGORY_TO_DOMAIN.get(raw_cat.strip().lower())
    if hinted and _taxonomy_key(hinted) in lookup:
        return hinted
    return raw_cat


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
        elif _rss.is_feed_url(low):
            # RSS/Atom (scrape_rss). Before the website/url fallbacks, which is
            # where these used to land: a feed downloaded as an opaque file
            # produced no records and no error, so the source looked fetched.
            # After the CWE test above, which is also .xml and has its own fetcher.
            kind = "rss"
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
    if kind == "rss":
        # metadata_only stamps the feed as a facts-only index (title/date/URL). Set
        # by a "Metadata Only" catalog column, or forced when the licence is the
        # metadata-index licence, so an All-Rights-Reserved feed cannot be
        # catalogued full-text by omitting the column.
        meta_only = (_bool(_val(row, "metadata_only"))
                     or "metadata index" in (lic or "").lower())
        return dict(kind="rss", domain=domain, slug=slug, title=name,
                    license=lic, url=url, metadata_only=meta_only)
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


def load_descriptors(spec: str, *, order_by_size: bool = True,
                     max_mb: float | None = None) -> list[dict]:
    """Read the catalog CSV at ``spec`` into a list of source descriptors.

    When ``order_by_size`` (the default), sources are returned smallest-first by
    their catalog size hint so the parallel run drains fast, small sources early
    and defers the multi-GB downloads, for quicker feedback and steadier progress.
    Rows with no recorded size sort last. Pass ``order_by_size=False`` to keep
    the catalog's original row order.

    When ``max_mb`` is set, sources whose catalog size is known to exceed it are
    skipped up front (never downloaded). Sources with no recorded size are kept,
    since their size can't be judged before fetching.
    """
    import pandas as pd

    path = _resolve(spec)
    # dtype=str + keep_default_na=False: every cell stays a string and blanks
    # stay "" (never NaN), so descriptor mapping sees clean text values.
    df = pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8")
    df = _norm_headers(df)
    pairs: list[tuple[float, dict]] = []
    skipped_oversize = 0
    for row in df.to_dict("records"):
        d = _row_to_descriptor(row)
        if d is None:
            continue
        sz = _size_hint(row)
        if max_mb is not None and sz != float("inf") and sz > max_mb:
            skipped_oversize += 1
            continue
        pairs.append((sz, d))
    if order_by_size:
        # stable sort keeps catalog order among equal-size sources
        pairs.sort(key=lambda p: p[0])
    out = [d for _sz, d in pairs]
    logger.info(f"loaded {len(out)} sources from {os.path.basename(path)}"
                + (" (smallest-first)" if order_by_size else ""))
    if skipped_oversize:
        logger.info(f"skipped {skipped_oversize} sources over the "
                    f"{max_mb / 1024:.1f} GB size cap")
    return out


def descriptor_key(d: dict) -> str:
    """Stable identity string for a source descriptor.

    Used to key the resume ledger (``completed_sources.txt``) so an interrupted
    build can skip work that already succeeded. hf/kaggle sources key on their
    ``kind:ref``; everything else keys on its URL (falling back to ``kind:slug``).
    """
    kind = d.get("kind")
    if kind in ("hf", "kaggle"):
        return f"{kind}:{d.get('ref')}"
    url = d.get("url") or d.get("start_url")
    if url:
        return str(url).strip()
    return f"{kind}:{d.get('ref') or d.get('slug')}"


# ---------------------------------------------------- synthetic-source lookup ---
# A source flagged ``Is Synthetic? = Yes`` in the catalog is model-generated,
# fabricated, or simulated data. It is still fetched + cleaned + counted by EDA,
# but the normalize stage drops its records from the final corpus (see
# ``normalize/synthetic.py``). Matching is by a stable *source identity* derived
# from a URL — the same ``/datasets/<org>/<name>`` ref the allowlist keys on — so
# a record maps back to its catalog row even when its ``url`` is a per-file
# ``/resolve/...`` link and even when the folder slug collides across datasets.

_DATASET_REF = re.compile(r"/datasets/([^/?#]+/[^/?#]+)")


def source_identity(url: str | None) -> str | None:
    """Normalized identity for a catalog ``Dataset Link`` or a record ``url``.

    HF/Kaggle dataset URLs collapse to ``<host>:<org>/<name>`` (host distinguishes
    ``hf`` from ``kaggle``); anything else collapses to ``url:<host><path>`` with
    scheme/``www.``/query/fragment/trailing-slash stripped. Returns ``None`` for an
    empty URL. Both the bare dataset link and its ``/resolve/main/...`` file form
    yield the same key, so catalog and record sides match exactly.
    """
    if not url:
        return None
    u = str(url).strip().lower()
    if not u:
        return None
    m = _DATASET_REF.search(u)
    if m:
        host = "hf" if "huggingface.co" in u else ("kaggle" if "kaggle.com" in u else "ds")
        return f"{host}:{m.group(1)}"
    u = re.sub(r"^https?://", "", u).split("?")[0].split("#")[0]
    u = u.removeprefix("www.").rstrip("/")
    return f"url:{u}" if u else None


def synthetic_identities(spec: str | None = None) -> frozenset[str]:
    """Identities of every catalog row flagged ``Is Synthetic? = Yes``.

    Reads the catalog CSV and returns the :func:`source_identity` of each flagged
    row's ``Dataset Link``. The normalize stage matches record URLs against this
    set to keep synthetic sources out of the final dataset.

    A missing catalog means nothing is flagged synthetic, not an error: normalize
    runs over ``data/clean``, which can exist without the catalog (a fresh
    checkout, an isolated test root, a corpus handed over without its sourcing
    sheet). Returning an empty set there keeps the stage running instead of
    failing it over a filter that simply has nothing to filter.
    """
    import pandas as pd

    path = spec or default_catalog()
    if not os.path.exists(path):
        logger.debug(f"synthetic_identities: no catalog at {path}; none flagged")
        return frozenset()
    path = _resolve(path)
    df = pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8")
    df = _norm_headers(df)
    ids: set[str] = set()
    for row in df.to_dict("records"):
        if not _bool(_val(row, "is_synthetic?", "is_synthetic")):
            continue
        ident = source_identity(_val(row, "dataset_link", "url", "link",
                                     "source_url"))
        if ident:
            ids.add(ident)
    return frozenset(ids)
