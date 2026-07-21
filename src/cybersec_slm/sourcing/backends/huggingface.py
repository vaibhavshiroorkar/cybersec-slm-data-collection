#!/usr/bin/env python3
"""HuggingFace datasets backend — license comes from the dataset card, never guessed.

Queries ``GET https://huggingface.co/api/datasets?search=<kw>`` and reads each
hit's ``license:<id>`` tag. When a hit carries no license tag the license is left
blank (Unknown) for the engine's enrich step — it is never invented.
"""

from __future__ import annotations

import time

import httpx

from ..search import Result
from .base import Backend, Candidate

HF_API = "https://huggingface.co/api/datasets"

# Normalize the common SPDX-ish HF license tags to the catalog's usual spelling.
_LICENSE_MAP = {
    "apache-2.0": "Apache-2.0", "mit": "MIT", "bsd-3-clause": "BSD-3-Clause",
    "cc-by-4.0": "CC BY 4.0", "cc-by-sa-4.0": "CC BY-SA 4.0", "cc0-1.0": "CC0 1.0",
    "cc-by-nc-4.0": "CC BY-NC 4.0", "gpl-3.0": "GPL-3.0", "openrail": "OpenRAIL",
}


def _license(tags: list[str]) -> str:
    for t in tags:
        if t.startswith("license:"):
            raw = t.split(":", 1)[1]
            if raw in ("unknown", "other", ""):
                return ""
            return _LICENSE_MAP.get(raw, raw)
    return ""


class HuggingFaceBackend(Backend):
    name = "huggingface"

    def search(self, subdomain, keyword, limit, cfg) -> list[Candidate]:
        bc = cfg.backends.get(self.name)
        limit = min(limit, bc.per_keyword_limit if bc else limit)
        out: list[Candidate] = []
        offset = 0
        try:
            with httpx.Client(timeout=30, follow_redirects=True) as client:
                while len(out) < limit:
                    resp = client.get(HF_API, params={
                        "search": keyword, "limit": 100, "offset": offset,
                        "full": "false"})
                    if resp.status_code != 200:
                        break
                    items = resp.json()
                    if not items:
                        break
                    for item in items:
                        if len(out) >= limit:
                            break
                        ds_id = item.get("id") or ""
                        if not ds_id:
                            continue
                        url = f"https://huggingface.co/datasets/{ds_id}"
                        desc = (item.get("description") or "").strip()[:300] \
                            or f"HuggingFace dataset: {ds_id}"
                        tags = item.get("tags") or []
                        dl = item.get("downloads")
                        out.append(Candidate(
                            subdomain=subdomain,
                            result=Result(title=ds_id, link=url, snippet=desc,
                                          display_link="huggingface.co"),
                            backend=self.name,
                            license=_license(tags),
                            author="huggingface.co",
                            popularity=str(int(dl)) if dl else "",
                            category="Dataset", fmt="JSONL",
                            note=f"HuggingFace dataset – kw:{keyword}"))
                    if len(items) < 100:
                        break
                    offset += 100
                    time.sleep(0.2)
        except httpx.HTTPError:
            pass
        return out
