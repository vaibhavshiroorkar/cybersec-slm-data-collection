#!/usr/bin/env python3
"""SearXNG metasearch client for sourcing.

Queries a self-hosted SearXNG instance's JSON API
(``$SEARXNG_URL/search?q=...&format=json``) and maps its results into the
``Result`` records the sourcing pipeline consumes. This replaces the former
Google Programmable Search backend: set ``SEARXNG_URL`` (default
``http://localhost:8080``) to point at your instance, which must allow the JSON
output format (``search: formats: [html, json]`` in its ``settings.yml``).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse

DEFAULT_BASE_URL = "http://localhost:8080"


@dataclass(frozen=True)
class Result:
    title: str
    link: str
    snippet: str
    display_link: str = ""


class SearchError(RuntimeError):
    """Raised when the search backend is misconfigured or returns an error."""


def base_url(url: str | None = None) -> str:
    """Resolve the SearXNG base URL (arg > ``$SEARXNG_URL`` > localhost:8080)."""
    return (url or os.environ.get("SEARXNG_URL") or DEFAULT_BASE_URL).rstrip("/")


def _host(link: str) -> str:
    try:
        return urlparse(link).netloc
    except ValueError:
        return ""


def _parse_items(payload: dict) -> list[Result]:
    """Map a SearXNG JSON payload (``{"results": [{url,title,content}, ...]}``)."""
    out: list[Result] = []
    for item in payload.get("results", []) or []:
        link = (item.get("url") or "").strip()
        if not link:
            continue
        out.append(Result(
            title=(item.get("title") or "").strip(),
            link=link,
            snippet=(item.get("content") or "").strip().replace("\n", " "),
            display_link=(item.get("displayLink") or _host(link)).strip(),
        ))
    return out


def searxng_search(query: str, *, url: str | None = None, num: int = 10,
                   categories: str = "general", language: str = "en",
                   client=None) -> list[Result]:
    """Search a SearXNG instance and return up to ``num`` results.

    ``url`` overrides ``$SEARXNG_URL``. ``client`` is an optional shared
    ``httpx.Client`` (search reuses it). Raises :class:`SearchError` when the
    instance is unreachable or has the JSON format disabled.
    """
    endpoint = base_url(url) + "/search"
    params = {"q": query, "format": "json", "categories": categories,
              "language": language}

    import httpx
    owns_client = client is None
    client = client or httpx.Client(timeout=30, follow_redirects=True)
    try:
        resp = client.get(endpoint, params=params,
                          headers={"Accept": "application/json"})
    except httpx.HTTPError as e:                       # network/timeout/DNS
        raise SearchError(
            f"SearXNG request to {endpoint} failed: {e}. Is SEARXNG_URL "
            f"({base_url(url)}) reachable?") from e
    finally:
        if owns_client:
            client.close()

    if resp.status_code == 403:
        raise SearchError(
            "SearXNG returned HTTP 403 for the JSON API. Enable it in the "
            "instance settings.yml (search: formats: [html, json]).")
    if resp.status_code != 200:
        raise SearchError(f"SearXNG HTTP {resp.status_code}: {resp.text[:200]}")

    try:
        payload = resp.json()
    except ValueError as e:
        raise SearchError(
            f"SearXNG did not return JSON (is the json format enabled?): {e}") from e

    return _parse_items(payload)[:max(1, int(num))]
