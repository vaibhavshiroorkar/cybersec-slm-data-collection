#!/usr/bin/env python3
"""GitHub repository search backend — license from ``repo.license.spdx_id`` only.

``GET https://api.github.com/search/repositories``. Authenticated via the env var
named by ``token_env`` (default ``GITHUB_TOKEN``) to raise the rate limit. A repo
with no detected license (``NOASSERTION``/none) is emitted with a blank license for
the enrich step — never a fabricated one.
"""

from __future__ import annotations

import os
import time

import httpx

from ..search import Result
from .base import Backend, Candidate

GH_API = "https://api.github.com/search/repositories"
_MAX_BACKOFF = 90.0


def _wait_seconds(resp: httpx.Response, default: float) -> float:
    ra = resp.headers.get("Retry-After")
    if ra:
        try:
            return min(float(ra), _MAX_BACKOFF)
        except ValueError:
            pass
    reset, remaining = resp.headers.get("X-RateLimit-Reset"), resp.headers.get("X-RateLimit-Remaining")
    if reset and remaining == "0":
        try:
            wait = float(reset) - time.time()
            if wait > 0:
                return min(wait + 1.0, _MAX_BACKOFF)
        except ValueError:
            pass
    return default


class GitHubBackend(Backend):
    name = "github"

    def search(self, subdomain, keyword, limit, cfg) -> list[Candidate]:
        bc = cfg.backends.get(self.name)
        limit = min(limit, bc.per_keyword_limit if bc else limit)
        token = os.environ.get((bc.token_env if bc else "") or "GITHUB_TOKEN", "")
        headers = {"Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        out: list[Candidate] = []
        page, retries = 1, 0
        try:
            with httpx.Client(timeout=(bc.timeout if bc else 15.0), follow_redirects=True) as client:
                while len(out) < limit and page <= 10:
                    resp = client.get(GH_API, params={
                        "q": keyword, "per_page": 100, "page": page,
                        "sort": "stars", "order": "desc"}, headers=headers)
                    if resp.status_code in (403, 429):
                        if retries >= 2:
                            break
                        time.sleep(_wait_seconds(resp, 10.0 if token else 30.0))
                        retries += 1
                        continue
                    if resp.status_code != 200:
                        break
                    retries = 0
                    data = resp.json()
                    items = data.get("items", [])
                    if not items:
                        break
                    for item in items:
                        if len(out) >= limit:
                            break
                        url = item.get("html_url", "")
                        if not url:
                            continue
                        full_name = item.get("full_name", "")
                        desc = (item.get("description") or "").strip()[:300] \
                            or f"GitHub repository: {full_name}"
                        lic_obj = item.get("license") or {}
                        lic = lic_obj.get("spdx_id") or lic_obj.get("name") or ""
                        if lic in ("NOASSERTION", ""):
                            lic = ""
                        stars = item.get("stargazers_count", 0)
                        out.append(Candidate(
                            subdomain=subdomain,
                            result=Result(title=full_name, link=url, snippet=desc,
                                          display_link="github.com"),
                            backend=self.name, license=lic,
                            author=(item.get("owner") or {}).get("login", "") or "github.com",
                            popularity=str(stars) if stars else "",
                            category="Repository",
                            note=f"GitHub repo – stars:{stars} – kw:{keyword}"))
                    if len(items) < 100 or data.get("total_count", 0) <= page * 100:
                        break
                    page += 1
                    time.sleep(1.0 if token else 6.0)
        except httpx.HTTPError:
            pass
        return out
