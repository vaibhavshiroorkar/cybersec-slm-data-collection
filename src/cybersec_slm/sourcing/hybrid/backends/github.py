"""
backends/github.py – GitHubBackend

Queries the GitHub Search Repositories API:
  GET https://api.github.com/search/repositories?q={q}&per_page=100&page={n}

Authenticated via `GITHUB_TOKEN` env var (or config.api_backends.github.token_env).
Without a token: 10 req/min. With a token: 30 req/min (search API).

Returns structured JSON with full_name, description, license, topics,
stargazers_count, html_url — no enrichment call needed.

Country inference: topic or description signals → primary country.
License: pulled directly from repo.license.spdx_id.

Rate-limit handling: on a 403/429 we read the standard GitHub rate-limit
headers (`Retry-After`, or `X-RateLimit-Reset`) and sleep exactly until the
window reopens (capped, so a clock-skew edge case can't stall the run for
minutes) instead of a blind fixed sleep, then retry the *same* page up to
twice before giving up on it — the old behaviour discarded the rest of that
keyword's results on the first 403 even though a short wait would recover them.
"""

from __future__ import annotations

import os
import time
from typing import Any

import httpx

from .base import Backend, make_row

GH_API = "https://api.github.com/search/repositories"
_MAX_BACKOFF = 90.0       # never sleep longer than this for one retry
_MAX_RETRIES_PER_PAGE = 2


def _rate_limit_wait_seconds(resp: httpx.Response, default: float) -> float:
    """Compute how long to sleep before retrying, from response headers."""
    retry_after = resp.headers.get("Retry-After")
    if retry_after:
        try:
            return min(float(retry_after), _MAX_BACKOFF)
        except ValueError:
            pass
    reset = resp.headers.get("X-RateLimit-Reset")
    remaining = resp.headers.get("X-RateLimit-Remaining")
    if reset and remaining == "0":
        try:
            wait = float(reset) - time.time()
            if wait > 0:
                return min(wait + 1.0, _MAX_BACKOFF)
        except ValueError:
            pass
    return default


class GitHubBackend(Backend):
    """Query GitHub repository search with keyword pagination."""

    name = "github"

    def fetch(
        self,
        keywords: dict[str, list[str]],
        needed: int,
        seen_urls: set[str],
        config: Any,
    ) -> list[dict[str, str]]:
        bc = config.api_backends.get("github")
        if bc is None or not bc.enabled:
            return []

        token_env = bc.token_env or "GITHUB_TOKEN"
        token = os.environ.get(token_env, "")
        headers = {"Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        signals = [s.lower() for s in bc.country_signal_keywords]
        primary = config.primary_country
        tags_str = config.default_tags
        rows: list[dict[str, str]] = []

        with httpx.Client(timeout=30, follow_redirects=True) as client:
            for subdomain, kw_list in keywords.items():
                for kw in kw_list:
                    if len(rows) >= needed:
                        break
                    page = 1
                    retries = 0
                    while len(rows) < needed and page <= 10:
                        try:
                            resp = client.get(GH_API, params={
                                "q": kw,
                                "per_page": 100,
                                "page": page,
                                "sort": "stars",
                                "order": "desc",
                            }, headers=headers)
                        except httpx.HTTPError:
                            break

                        if resp.status_code in (403, 429):
                            if retries >= _MAX_RETRIES_PER_PAGE:
                                break  # genuinely stuck — move to next keyword
                            wait = _rate_limit_wait_seconds(
                                resp, default=10.0 if token else 30.0)
                            time.sleep(wait)
                            retries += 1
                            continue  # retry the same page
                        if resp.status_code != 200:
                            break

                        retries = 0  # reset once a page succeeds
                        data = resp.json()
                        items = data.get("items", [])
                        if not items:
                            break

                        for item in items:
                            if len(rows) >= needed:
                                break
                            url = item.get("html_url", "")
                            if not url or url in seen_urls:
                                continue
                            seen_urls.add(url)

                            full_name = item.get("full_name", "")
                            desc = (item.get("description") or "").strip()[:300]
                            if not desc:
                                desc = f"GitHub repository: {full_name}"

                            # License
                            lic_obj = item.get("license") or {}
                            lic = lic_obj.get("spdx_id") or lic_obj.get("name") or "Unknown"
                            if lic in ("NOASSERTION", ""):
                                lic = "Unknown"

                            # Stars for popularity
                            stars = item.get("stargazers_count", 0)

                            # Country inference
                            topics = item.get("topics") or []
                            text = f"{full_name} {desc} {' '.join(topics)}".lower()
                            country = primary if (signals and any(s in text for s in signals)) else "Global"

                            rows.append(make_row(
                                name=full_name,
                                subdomain=subdomain,
                                country=country,
                                description=desc,
                                url=url,
                                field=config.field,
                                category="Dataset",
                                fmt="Various",
                                license_=lic,
                                author="github.com",
                                tags=tags_str,
                                note=f"GitHub repo – ⭐{stars} – kw:{kw}",
                            ))

                        if len(items) < 100 or data.get("total_count", 0) <= page * 100:
                            break
                        page += 1
                        time.sleep(1.0 if token else 6.0)

        return rows