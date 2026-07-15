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


# SearXNG's recognized ``time_range`` values (freshness filter); anything else is
# treated as "no time filter".
_TIME_RANGES = {"day", "week", "month", "year"}


def searxng_search(query: str, *, url: str | None = None, num: int = 10,
                   categories: str = "general", language: str = "en",
                   pageno: int = 1, time_range: str | None = None,
                   engines: str | None = None,
                   client=None, retries: int = 2) -> list[Result]:
    """Search a SearXNG instance and return up to ``num`` results.

    ``url`` overrides ``$SEARXNG_URL``. ``pageno`` (1-based) selects the result
    page, so a caller can walk deeper through the engine's results to keep
    gathering beyond the first page. ``time_range`` (``day``/``week``/``month``/
    ``year``) applies SearXNG's freshness filter; any other value is ignored.
    ``engines`` (a comma-separated engine list, e.g. ``"github,arxiv"``) targets
    specific SearXNG engines; when set, the instance uses those engines instead of
    the ``categories`` default. This is how the pipeline routes around the
    rate-limited general web engines to the reliable API ones. ``client`` is an
    optional shared ``httpx.Client`` (search reuses it). ``retries`` transient
    network errors are retried with a short backoff before a :class:`SearchError`
    is raised. Raises :class:`SearchError` when the instance is unreachable or has
    the JSON format disabled.
    """
    endpoint = base_url(url) + "/search"
    params = {"q": query, "format": "json", "categories": categories,
              "language": language, "pageno": max(1, int(pageno))}
    if time_range in _TIME_RANGES:
        params["time_range"] = time_range
    if engines:
        params["engines"] = engines

    import time as _time

    import httpx
    owns_client = client is None
    client = client or httpx.Client(timeout=30, follow_redirects=True)
    try:
        resp = None
        last_err: Exception | None = None
        for attempt in range(max(1, retries + 1)):
            try:
                resp = client.get(endpoint, params=params,
                                  headers={"Accept": "application/json"})
                break
            except httpx.HTTPError as e:              # network/timeout/DNS
                last_err = e
                if attempt < retries:
                    _time.sleep(0.5 * (attempt + 1))  # brief backoff, then retry
        if resp is None:
            raise SearchError(
                f"SearXNG request to {endpoint} failed: {last_err}. Is SEARXNG_URL "
                f"({base_url(url)}) reachable?") from last_err
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
