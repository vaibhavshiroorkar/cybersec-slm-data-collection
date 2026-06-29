#!/usr/bin/env python3
"""Google Programmable Search (Custom Search JSON API) client for sourcing."""

from __future__ import annotations

import os
from dataclasses import dataclass

ENDPOINT = "https://www.googleapis.com/customsearch/v1"


@dataclass(frozen=True)
class Result:
    title: str
    link: str
    snippet: str
    display_link: str = ""


class SearchError(RuntimeError):
    """Raised when the search backend is misconfigured or returns an error."""


def _parse_items(payload: dict) -> list[Result]:
    out: list[Result] = []
    for item in payload.get("items", []) or []:
        link = (item.get("link") or "").strip()
        if not link:
            continue
        out.append(Result(
            title=(item.get("title") or "").strip(),
            link=link,
            snippet=(item.get("snippet") or "").strip().replace("\n", " "),
            display_link=(item.get("displayLink") or "").strip(),
        ))
    return out


def google_search(query: str, *, api_key: str | None = None,
                  cse_id: str | None = None, num: int = 10,
                  client=None) -> list[Result]:
    api_key = (api_key or os.environ.get("GOOGLE_SEARCH_API_KEY")
               or os.environ.get("GOOGLE_API_KEY"))
    cse_id = (cse_id or os.environ.get("GOOGLE_SEARCH_ENGINE_ID")
              or os.environ.get("GOOGLE_CSE_ID"))
    if not api_key or not cse_id:
        raise SearchError(
            "Google search needs GOOGLE_SEARCH_API_KEY and GOOGLE_SEARCH_ENGINE_ID. "
            "Create an API key with the Custom Search API enabled and a Programmable "
            "Search Engine (cx) set to search the entire web.")

    params = {"key": api_key, "cx": cse_id, "q": query,
              "num": max(1, min(int(num), 10))}

    import httpx
    owns_client = client is None
    client = client or httpx.Client(timeout=30)
    try:
        resp = client.get(ENDPOINT, params=params)
    except httpx.HTTPError as e:                       # network/timeout
        raise SearchError(f"search request failed: {e}") from e
    finally:
        if owns_client:
            client.close()

    if resp.status_code != 200:
        detail = ""
        try:
            detail = resp.json().get("error", {}).get("message", "")
        except Exception:
            detail = resp.text[:200]
        raise SearchError(f"search HTTP {resp.status_code}: {detail}")

    return _parse_items(resp.json())
