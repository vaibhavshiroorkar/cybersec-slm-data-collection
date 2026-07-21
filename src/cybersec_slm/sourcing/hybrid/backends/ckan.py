"""
backends/ckan.py – CKANBackend

Queries any CKAN data portal's package_search action:
  POST {base_url}/api/3/action/package_search?q={q}&rows=100&start={n}

Primary target: data.gov.in (India open government data), whose packages
carry the Government Open Data License – India (GODL), which grants
commercial reuse. API key is optional on some portals but required on
data.gov.in for large result sets.

Country and license are set from the backend config (not inferred), since
a CKAN portal's geographical and licensing scope is known at config time.
"""

from __future__ import annotations

import os
import time
from typing import Any

import httpx

from .base import Backend, make_row


class CKANBackend(Backend):
    """Query a CKAN open-data portal with per-keyword pagination."""

    name = "ckan"

    def fetch(
        self,
        keywords: dict[str, list[str]],
        needed: int,
        seen_urls: set[str],
        config: Any,
    ) -> list[dict[str, str]]:
        bc = config.api_backends.get("ckan")
        if bc is None or not bc.enabled:
            return []

        base = bc.base_url.rstrip("/")
        if not base:
            return []

        api_key = ""
        if bc.api_key_env:
            api_key = os.environ.get(bc.api_key_env, "")

        country = bc.country or config.primary_country
        license_ = bc.license or "Government Open Data License - India (GODL)"
        tags_str = config.default_tags
        rows: list[dict[str, str]] = []

        headers: dict[str, str] = {}
        if api_key:
            headers["Authorization"] = api_key

        with httpx.Client(timeout=30, follow_redirects=True) as client:
            for subdomain, kw_list in keywords.items():
                for kw in kw_list:
                    if len(rows) >= needed:
                        break
                    start = 0
                    while len(rows) < needed:
                        try:
                            resp = client.get(
                                f"{base}/api/3/action/package_search",
                                params={"q": kw, "rows": 100, "start": start},
                                headers=headers,
                            )
                        except httpx.HTTPError:
                            break
                        if resp.status_code not in (200, 201):
                            break

                        data = resp.json()
                        result = data.get("result") or {}
                        packages = result.get("results", [])
                        if not packages:
                            break

                        for pkg in packages:
                            if len(rows) >= needed:
                                break
                            name_slug = pkg.get("name") or pkg.get("id") or ""
                            url = f"{base}/dataset/{name_slug}"
                            if url in seen_urls:
                                continue
                            seen_urls.add(url)

                            title = (pkg.get("title") or name_slug).strip()
                            desc = (pkg.get("notes") or pkg.get("description") or "").strip()[:300]
                            if not desc:
                                desc = f"CKAN dataset: {title}"

                            # Override license with portal-level license from config
                            pkg_lic = pkg.get("license_id") or pkg.get("license_title") or ""
                            final_lic = license_ if license_ else pkg_lic or "Unknown"

                            rows.append(make_row(
                                name=title[:80],
                                subdomain=subdomain,
                                country=country,
                                description=desc,
                                url=url,
                                field=config.field,
                                category="Dataset",
                                fmt="Various",
                                license_=final_lic,
                                author=base.removeprefix("https://").removeprefix("http://"),
                                tags=tags_str,
                                note=f"CKAN open data portal – kw:{kw}",
                            ))

                        total = result.get("count", 0)
                        if len(packages) < 100 or start + 100 >= total:
                            break
                        start += 100
                        time.sleep(0.5)

        return rows
