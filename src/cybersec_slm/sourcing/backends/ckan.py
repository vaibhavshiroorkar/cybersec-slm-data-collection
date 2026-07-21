#!/usr/bin/env python3
"""CKAN open-data portal backend — license from the package, then the portal.

``GET {base_url}/api/3/action/package_search``. Each package's own
``license_id``/``license_title`` is used when present; only when a package exposes
none does it fall back to the portal-level license — a genuine portal fact (e.g.
data.gov.in is wholly GODL-India), configured via ``backends.ckan.extra.license``,
not a per-URL guess. Absent both, the license is blank for the enrich step.
"""

from __future__ import annotations

import os
import time

import httpx

from ..search import Result
from .base import Backend, Candidate


class CKANBackend(Backend):
    name = "ckan"

    def available(self, cfg) -> bool:
        bc = cfg.backends.get(self.name)
        return bool(bc and bc.enabled and bc.base_url)

    def search(self, subdomain, keyword, limit, cfg) -> list[Candidate]:
        bc = cfg.backends.get(self.name)
        if not bc or not bc.base_url:
            return []
        limit = min(limit, bc.per_keyword_limit)
        base = bc.base_url.rstrip("/")
        portal_license = str(bc.extra.get("license", "")).strip()
        headers: dict[str, str] = {}
        if bc.api_key_env and os.environ.get(bc.api_key_env):
            headers["Authorization"] = os.environ[bc.api_key_env]

        out: list[Candidate] = []
        start = 0
        try:
            with httpx.Client(timeout=bc.timeout, follow_redirects=True) as client:
                while len(out) < limit:
                    resp = client.get(f"{base}/api/3/action/package_search",
                                      params={"q": keyword, "rows": 100, "start": start},
                                      headers=headers)
                    if resp.status_code not in (200, 201):
                        break
                    result = (resp.json().get("result") or {})
                    packages = result.get("results", [])
                    if not packages:
                        break
                    for pkg in packages:
                        if len(out) >= limit:
                            break
                        slug = pkg.get("name") or pkg.get("id") or ""
                        if not slug:
                            continue
                        url = f"{base}/dataset/{slug}"
                        title = (pkg.get("title") or slug).strip()
                        desc = (pkg.get("notes") or "").strip()[:300] or f"CKAN dataset: {title}"
                        lic = (pkg.get("license_id") or pkg.get("license_title") or "").strip()
                        if not lic:
                            lic = portal_license
                        out.append(Candidate(
                            subdomain=subdomain,
                            result=Result(title=title[:80], link=url, snippet=desc,
                                          display_link=base.split("//")[-1]),
                            backend=self.name, license=lic,
                            author=base.split("//")[-1].removeprefix("www."),
                            country=str(bc.extra.get("country", "")).strip(),
                            category="Dataset",
                            note=f"CKAN portal – kw:{keyword}"))
                    total = result.get("count", 0)
                    if len(packages) < 100 or start + 100 >= total:
                        break
                    start += 100
                    time.sleep(0.5)
        except httpx.HTTPError:
            pass
        return out
