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


def _lic_str(lic) -> str:
    """A license cell from a str / list value (HF cardData can hold either)."""
    if isinstance(lic, (list, tuple)):
        lic = next((x for x in lic if x), "")
    return str(lic).strip()


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

    card = getattr(info, "cardData", None) or {}
    lic = None
    try:
        lic = card.get("license")
    except AttributeError:
        lic = getattr(card, "license", None)
    if not lic:
        for t in getattr(info, "tags", None) or []:
            if isinstance(t, str) and t.startswith("license:"):
                lic = t.split(":", 1)[1]
                break
    if lic:
        out["License"] = _lic_str(lic)

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

    lic = (d.get("license") or {}).get("spdx_id")
    if lic and lic != "NOASSERTION":
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
    return out


class Enricher:
    """Metadata fetcher for a discovery run: shared client + GitHub rate-limit state.

    One instance per run. ``enrich(row)`` fills any blank metadata columns of a
    catalog row from its ``Dataset Link``; it never raises and never overwrites a
    value discovery already set.
    """

    def __init__(self, *, client=None, github_token: str | None = None,
                 timeout: float = 8.0):
        self._client = client
        self._token = github_token or os.getenv("GITHUB_TOKEN") or None
        self._timeout = timeout
        self._github_ok = True

    def enrich(self, row: dict) -> dict:
        link = (row.get("Dataset Link") or "").strip()
        if not link:
            return row
        meta: dict = {}
        try:
            hf = _HF_RE.search(link)
            gh = _GH_RE.search(link)
            if hf:
                meta = _enrich_hf(hf.group(1))
            elif gh and gh.group(1).lower() not in _GH_SKIP:
                if self._github_ok:
                    repo = re.sub(r"\.git$", "", gh.group(2))
                    meta = _enrich_github(gh.group(1), repo, client=self._client,
                                          token=self._token, timeout=self._timeout)
            else:
                meta = _enrich_url(link, client=self._client, timeout=self._timeout)
        except _RateLimited:
            self._github_ok = False
            logger.info("enrich: GitHub rate limit hit; skipping GitHub for the "
                        "rest of this run (set $GITHUB_TOKEN to raise the limit)")
        except Exception as e:                          # noqa: BLE001 - best-effort
            logger.debug(f"enrich: {link}: {type(e).__name__}: {e}")
        for k, v in meta.items():
            if v not in (None, "") and not row.get(k):
                row[k] = v
        return row


def enrich_row(row: dict, *, client=None, github_token: str | None = None,
               timeout: float = 8.0) -> dict:
    """One-shot convenience wrapper around :class:`Enricher` for a single row."""
    return Enricher(client=client, github_token=github_token,
                    timeout=timeout).enrich(row)
