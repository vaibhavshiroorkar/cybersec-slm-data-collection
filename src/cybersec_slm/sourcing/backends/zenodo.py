#!/usr/bin/env python3
"""Zenodo records backend — license from ``metadata.license.id`` (real SPDX id).

``GET https://zenodo.org/api/records``. Zenodo requires every published record to
declare a license, so this backend has a genuine license for nearly every hit; an
optional ``ZENODO_TOKEN`` raises the anonymous rate limit. A record with no license
id is emitted blank for the enrich step.
"""

from __future__ import annotations

import os
import re
import time

import httpx

from ..search import Result
from .base import Backend, Candidate

ZENODO_API = "https://zenodo.org/api/records"

_LICENSE_MAP = {
    "cc-by-4.0": "CC BY 4.0", "cc-by-sa-4.0": "CC BY-SA 4.0",
    "cc-by-nc-4.0": "CC BY-NC 4.0", "cc0-1.0": "CC0 1.0", "cc-zero": "CC0 1.0",
    "mit": "MIT", "apache-2.0": "Apache-2.0", "bsd-3-clause": "BSD-3-Clause",
    "gpl-3.0": "GPL-3.0",
}
_TAG_RE = re.compile(r"<[^>]+>")


def _license(meta: dict) -> str:
    lic = (meta.get("license") or {})
    raw = (lic.get("id") if isinstance(lic, dict) else str(lic)) or ""
    raw = raw.strip().lower()
    if not raw:
        return ""
    return _LICENSE_MAP.get(raw, raw)


class ZenodoBackend(Backend):
    name = "zenodo"

    def search(self, subdomain, keyword, limit, cfg) -> list[Candidate]:
        bc = cfg.backends.get(self.name)
        limit = min(limit, bc.per_keyword_limit if bc else limit)
        # Sort by relevance to the query, not recency: 'mostrecent' returns the
        # newest records regardless of topical match, which floods the catalog with
        # off-subject datasets.
        params = {"q": keyword, "size": min(100, limit), "page": 1, "sort": "bestmatch"}
        token = os.environ.get("ZENODO_TOKEN", "")
        if token:
            params["access_token"] = token
        out: list[Candidate] = []
        try:
            with httpx.Client(timeout=30, follow_redirects=True) as client:
                while len(out) < limit:
                    resp = client.get(ZENODO_API, params=params)
                    if resp.status_code != 200:
                        break
                    hits = ((resp.json().get("hits") or {}).get("hits")) or []
                    if not hits:
                        break
                    for rec in hits:
                        if len(out) >= limit:
                            break
                        meta = rec.get("metadata") or {}
                        url = (rec.get("links") or {}).get("html") or rec.get("doi_url") or ""
                        if not url:
                            continue
                        title = (meta.get("title") or "").strip()
                        desc = _TAG_RE.sub(" ", meta.get("description") or "").strip()[:300] \
                            or f"Zenodo record: {title}"
                        creators = meta.get("creators") or []
                        author = creators[0].get("name", "") if creators else "zenodo.org"
                        out.append(Candidate(
                            subdomain=subdomain,
                            result=Result(title=title[:80], link=url, snippet=desc,
                                          display_link="zenodo.org"),
                            backend=self.name, license=_license(meta),
                            author=author or "zenodo.org",
                            last_updated=(meta.get("publication_date") or "")[:10],
                            category="Dataset",
                            note=f"Zenodo record – kw:{keyword}"))
                    if len(hits) < params["size"]:
                        break
                    params["page"] += 1
                    time.sleep(0.5)
        except httpx.HTTPError:
            pass
        return out
