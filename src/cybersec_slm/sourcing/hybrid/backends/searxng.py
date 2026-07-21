"""
backends/searxng.py – SearXNGBackend

Wraps the existing sourcing.search.searxng_search() client with:
  - Multi-page pagination (up to config max_pages)
  - Per-keyword quality pre-filter (no listing pages, no junk hosts)
  - Graceful degradation when SearXNG is unreachable

SearXNG is the discovery-of-last-resort backend. It is useful for finding
sources that are not on HuggingFace/GitHub/arXiv, but it is rate-limited
and noisy. The scorer handles relevance filtering after this backend returns.

The SearXNG URL is resolved from:
  1. config.api_backends.searxng.url (from YAML)
  2. SEARXNG_URL environment variable
  3. http://localhost:8080 (default)
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

import httpx

from .base import Backend, make_row

_JUNK_HOSTS = {
    "pinterest.com", "facebook.com", "twitter.com", "x.com",
    "youtube.com", "reddit.com", "instagram.com", "tiktok.com",
    "linkedin.com", "quora.com",
}
_LISTING_SEGMENTS = {"search", "tag", "tags", "topic", "topics",
                     "category", "categories", "label", "labels"}


def _is_junk(url: str) -> bool:
    try:
        p = urlparse(url)
        host = p.netloc.lower().removeprefix("www.")
        if any(host == j or host.endswith("." + j) for j in _JUNK_HOSTS):
            return True
        segs = {s for s in p.path.lower().split("/") if s}
        if segs & _LISTING_SEGMENTS:
            return True
        if "q=" in p.query:
            return True
    except Exception:
        pass
    return False


def _searxng_search(endpoint: str, query: str, engines: str,
                    pageno: int, client: httpx.Client) -> list[dict]:
    """Call SearXNG JSON API and return raw result dicts."""
    params = {
        "q": query,
        "format": "json",
        "categories": "general",
        "pageno": pageno,
    }
    if engines:
        params["engines"] = engines
    try:
        resp = client.get(f"{endpoint}/search", params=params,
                          headers={"Accept": "application/json"}, timeout=30)
        if resp.status_code == 200:
            return resp.json().get("results", [])
    except Exception:
        pass
    return []


class SearXNGBackend(Backend):
    """Discover sources via a self-hosted SearXNG instance."""

    name = "searxng"

    def fetch(
        self,
        keywords: dict[str, list[str]],
        needed: int,
        seen_urls: set[str],
        config: Any,
    ) -> list[dict[str, str]]:
        bc = config.api_backends.get("searxng")
        if bc is None or not bc.enabled:
            return []

        import os
        endpoint = (
            bc.searxng_url
            or os.environ.get("SEARXNG_URL", "")
            or "http://localhost:8080"
        ).rstrip("/")

        engines = bc.engines
        max_pages = bc.max_pages
        per_kw = bc.per_keyword_limit
        signals = [s.lower() for s in bc.country_signal_keywords]
        primary = config.primary_country
        tags_str = config.default_tags
        rows: list[dict[str, str]] = []

        with httpx.Client(timeout=30, follow_redirects=True) as client:
            for subdomain, kw_list in keywords.items():
                for kw in kw_list:
                    if len(rows) >= needed:
                        break
                    fetched = 0
                    for page in range(1, max_pages + 1):
                        if len(rows) >= needed or fetched >= per_kw:
                            break
                        results = _searxng_search(endpoint, kw, engines, page, client)
                        if not results:
                            break

                        for item in results:
                            if len(rows) >= needed or fetched >= per_kw:
                                break
                            url = (item.get("url") or "").strip()
                            if not url or url in seen_urls:
                                continue
                            if _is_junk(url):
                                continue
                            seen_urls.add(url)
                            fetched += 1

                            title = (item.get("title") or "").strip()[:80]
                            snippet = (item.get("content") or "").strip()[:300]
                            if not title:
                                title = url[:80]

                            text = f"{title} {snippet}".lower()
                            country = primary if (signals and any(s in text for s in signals)) else "Global"

                            rows.append(make_row(
                                name=title,
                                subdomain=subdomain,
                                country=country,
                                description=snippet,
                                url=url,
                                field=config.field,
                                category="Document",
                                fmt="HTML",
                                license_="Unknown",
                                author=urlparse(url).netloc.removeprefix("www."),
                                tags=tags_str,
                                note=f"SearXNG discovery – kw:{kw} – page:{page}",
                            ))

                        time.sleep(1.0)

        return rows
