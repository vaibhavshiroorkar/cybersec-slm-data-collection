#!/usr/bin/env python3
"""Fetch per-source metadata for a freshly discovered catalog row.

Discovery (``sourcing/run.py``) knows only what SearXNG returns. This module hits
each source host to fill the metadata columns of ``Sources.csv``: License, Last
Updated, Original Size (MB), File Count, plus Author / Popularity / Tags. Three
hosts are handled - HuggingFace datasets (via ``huggingface_hub``, the dependency
``ingestion/fetch.py`` already uses), GitHub repos (the REST API over ``httpx``,
honoring ``$GITHUB_TOKEN``), and any other direct URL (an HTTP ``HEAD``).

Best-effort by contract: every network or parse failure is swallowed (logged at
debug) and leaves the field blank, so enrichment can never abort a discovery run.
A GitHub rate-limit (403) disables further GitHub calls for the rest of the run.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

from ..core import logger
from .license_detect import detect_license, license_from_github_json, license_from_hf_info


def _host_of(link: str) -> str:
    """Bare, lowercased host of a link, without port or a ``www.`` prefix."""
    try:
        netloc = urlparse(link if "://" in link else "//" + link).netloc
    except ValueError:
        return ""
    return netloc.split("@")[-1].split(":")[0].lower().removeprefix("www.")

_HF_RE = re.compile(r"huggingface\.co/datasets/([^/?#]+/[^/?#]+)", re.IGNORECASE)
_GH_RE = re.compile(r"github\.com/([^/?#]+)/([^/?#]+)", re.IGNORECASE)
_GH_SKIP = {"orgs", "search", "topics", "about", "features", "marketplace"}

# Data-file extensions worth counting/sizing on HuggingFace (mirrors ingestion).
_DATA_EXTS = (".jsonl", ".json", ".parquet", ".csv", ".tsv", ".txt", ".arrow")
# HuggingFace namespaces machine metadata as "prefix:value" tags (license:*,
# library:*, size_categories:*, task_categories:*, ...); the human-meaningful tags
# carry no colon. GitHub topics never contain one. So a colon marks a machine tag.
_MAX_TAGS = 8


def _fmt_date(v) -> str:
    """Normalize a datetime / ISO string / HTTP-date to ``YYYY-MM-DD`` (else '')."""
    if not v:
        return ""
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d")
    s = str(v)
    m = re.match(r"(\d{4}-\d{2}-\d{2})", s)
    if m:
        return m.group(1)
    try:
        return parsedate_to_datetime(s).strftime("%Y-%m-%d")
    except (TypeError, ValueError):
        return ""


def _clean_tags(tags) -> str:
    """Comma-join meaningful tags, dropping machine prefixes; capped in count/len."""
    keep: list[str] = []
    for t in tags or []:
        t = str(t).strip()
        if not t or ":" in t:                       # skip machine (namespaced) tags
            continue
        keep.append(t)
        if len(keep) >= _MAX_TAGS:
            break
    return ", ".join(keep)[:200]


def _is_data_file(name: str) -> bool:
    n = name.lower()
    return n.endswith(_DATA_EXTS)


class _RateLimited(Exception):
    """Raised on a GitHub 403 so the caller can stop calling GitHub this run."""


def _enrich_hf(ref: str) -> dict:
    from huggingface_hub import HfApi

    info = HfApi().dataset_info(ref, files_metadata=True)
    out: dict[str, str] = {}

    lic = license_from_hf_info(info)          # shared normalizer (sourcing.license_detect)
    if lic:
        out["License"] = lic

    if getattr(info, "lastModified", None):
        out["Last Updated"] = _fmt_date(info.lastModified)

    data_files = [s for s in (getattr(info, "siblings", None) or [])
                  if _is_data_file(getattr(s, "rfilename", "") or "")]
    total = sum((getattr(s, "size", 0) or 0) for s in data_files)
    if total:
        out["Original Size (MB)"] = f"{total / 1048576:.2f}"
    if data_files:
        out["File Count"] = str(len(data_files))

    author = getattr(info, "author", None) or ref.split("/")[0]
    if author:
        out["Author"] = str(author)
    dl = getattr(info, "downloads", None)
    if dl:
        out["Popularity"] = str(int(dl))
    tags = _clean_tags(getattr(info, "tags", None) or [])
    if tags:
        out["Tags"] = tags
    return out


def _enrich_github(owner: str, repo: str, *, client=None, token=None,
                   timeout: float = 8.0) -> dict:
    import httpx

    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"https://api.github.com/repos/{owner}/{repo}"
    resp = (client.get(url, headers=headers, timeout=timeout) if client
            else httpx.get(url, headers=headers, timeout=timeout))
    if resp.status_code == 403:
        raise _RateLimited("github rate limit")
    resp.raise_for_status()
    d = resp.json()
    out: dict[str, str] = {}

    lic = license_from_github_json(d)          # shared normalizer
    if lic:
        out["License"] = lic
    if d.get("pushed_at"):
        out["Last Updated"] = _fmt_date(d["pushed_at"])
    if d.get("size"):                       # GitHub repo size is in KB
        out["Original Size (MB)"] = f"{d['size'] / 1024:.2f}"
    owner_login = (d.get("owner") or {}).get("login")
    if owner_login:
        out["Author"] = owner_login
    if d.get("stargazers_count") is not None:
        out["Popularity"] = str(d["stargazers_count"])
    tags = _clean_tags(d.get("topics") or [])
    if tags:
        out["Tags"] = tags
    return out


def _enrich_url(url: str, *, client=None, timeout: float = 8.0) -> dict:
    import httpx

    resp = (client.head(url, timeout=timeout, follow_redirects=True) if client
            else httpx.head(url, timeout=timeout, follow_redirects=True))
    out: dict[str, str] = {}
    cl = resp.headers.get("Content-Length")
    if cl and str(cl).isdigit() and int(cl) > 0:
        out["Original Size (MB)"] = f"{int(cl) / 1048576:.2f}"
        out["File Count"] = "1"
    if resp.headers.get("Last-Modified"):
        out["Last Updated"] = _fmt_date(resp.headers["Last-Modified"])
    host = urlparse(url).netloc.removeprefix("www.")
    if host:
        out["Author"] = host
    # A HEAD carries no license, so deep-detect it from the page (Kaggle/arXiv/
    # generic HTML). Best-effort - a miss just leaves the column blank.
    lic = detect_license(url, client=client, timeout=timeout)
    if lic:
        out["License"] = lic
    return out


class Enricher:
    """Metadata fetcher for a discovery run: shared client + GitHub rate-limit state.

    One instance per run. ``enrich(row)`` fills any blank metadata columns of a
    catalog row from its ``Dataset Link``; it never raises and never overwrites a
    value discovery already set.
    """

    def __init__(self, *, client=None, timeout: float = 8.0):
        import threading

        self._client = client
        self._timeout = timeout
        self._github_ok = True
        # ``enrich`` is called concurrently from a discovery thread pool; the only
        # shared mutable state is the GitHub rate-limit flag, guarded by this lock.
        self._lock = threading.Lock()

    def enrich(self, row: dict) -> dict:
        link = (row.get("Dataset Link") or "").strip()
        if not link:
            return row

        # Content we own needs no licence lookup: there is no third-party grant to
        # find, and scraping the page would only yield "unknown", which the gate
        # (default-deny) then turns away — silently discarding the very sources the
        # owner authorized. Stamp it instead. Keyed on the host against the
        # profile's owned_hosts, never on anything the page says.
        from . import keywords as _kw
        from .taxonomies import OWNED_LICENSE
        if _kw.is_owned(_host_of(link)):
            row["License"] = OWNED_LICENSE
            return row

        meta: dict = {}
        try:
            hf = _HF_RE.search(link)
            gh = _GH_RE.search(link)
            if hf:
                meta = _enrich_hf(hf.group(1))
            elif gh and gh.group(1).lower() not in _GH_SKIP:
                with self._lock:
                    github_ok = self._github_ok
                if github_ok:
                    repo = re.sub(r"\.git$", "", gh.group(2))
                    token_env = row.get("Credential Ref") or "GITHUB_TOKEN"
                    token = os.environ.get(token_env)
                    meta = _enrich_github(gh.group(1), repo, client=self._client,
                                          token=token, timeout=self._timeout)
            else:
                meta = _enrich_url(link, client=self._client, timeout=self._timeout)
        except _RateLimited:
            with self._lock:
                self._github_ok = False
            logger.info("enrich: GitHub rate limit hit; skipping GitHub for the "
                        "rest of this run (set $GITHUB_TOKEN to raise the limit)")
        except Exception as e:                          # noqa: BLE001 - best-effort
            logger.debug(f"enrich: {link}: {type(e).__name__}: {e}")
        for k, v in meta.items():
            if v not in (None, "") and not row.get(k):
                row[k] = v
        return row


def enrich_row(row: dict, *, client=None,
               timeout: float = 8.0) -> dict:
    """Enrich one row synchronously (convenience wrapper)."""
    return Enricher(client=client, timeout=timeout).enrich(row)
