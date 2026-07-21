"""
backends/huggingface.py – HuggingFaceBackend

Queries the HuggingFace public Datasets API directly:
  GET https://huggingface.co/api/datasets?search={q}&limit=100&offset={n}

Returns structured JSON with name, description, tags, downloads — no
enrichment HTTP call needed. Paginated with `offset` so a single keyword
can yield hundreds of results.

Country inference: if the dataset name/description/tags contain any of the
config's `country_signal_keywords` → mark as primary country; otherwise
"Global".

License: mapped from the HuggingFace `cardData.license` field via a simple
SPDX lookup table.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from .base import Backend, make_row

HF_API = "https://huggingface.co/api/datasets"

_LICENSE_MAP = {
    "apache-2.0": "Apache-2.0",
    "mit": "MIT",
    "cc-by-4.0": "CC BY 4.0",
    "cc-by-sa-4.0": "CC BY-SA 4.0",
    "cc0-1.0": "CC0 1.0",
    "cc-by-nc-4.0": "CC BY-NC 4.0",
    "gpl-3.0": "GPL-3.0",
    "lgpl-3.0": "LGPL-3.0",
    "openrail": "OpenRAIL",
    "llama2": "Llama 2 Community License",
    "unknown": "Unknown",
    "other": "Other",
}


def _map_license(raw: str | None) -> str:
    if not raw:
        return "Unknown"
    return _LICENSE_MAP.get(raw.lower(), raw)


def _infer_country(name: str, desc: str, tags: list[str],
                   signals: list[str]) -> tuple[str, str]:
    """Return (country, note) based on signal keyword matching."""
    text = f"{name} {desc} {' '.join(tags)}".lower()
    if any(s in text for s in signals):
        return "", "country-signal match"   # caller fills in primary_country
    return "Global", ""


class HuggingFaceBackend(Backend):
    """Query HuggingFace /api/datasets with per-keyword pagination."""

    name = "huggingface"

    def fetch(
        self,
        keywords: dict[str, list[str]],
        needed: int,
        seen_urls: set[str],
        config: Any,
    ) -> list[dict[str, str]]:
        bc = config.api_backends.get("huggingface")
        if bc is None or not bc.enabled:
            return []

        limit = min(bc.per_keyword_limit, 100)
        signals = [s.lower() for s in bc.country_signal_keywords]
        primary = config.primary_country
        tags_str = config.default_tags

        rows: list[dict[str, str]] = []

        with httpx.Client(timeout=30, follow_redirects=True) as client:
            for subdomain, kw_list in keywords.items():
                for kw in kw_list:
                    if len(rows) >= needed:
                        break
                    offset = 0
                    while len(rows) < needed:
                        try:
                            resp = client.get(HF_API, params={
                                "search": kw,
                                "limit": 100,
                                "offset": offset,
                                "full": "false",
                            })
                        except httpx.HTTPError:
                            break
                        if resp.status_code != 200:
                            break
                        items = resp.json()
                        if not items:
                            break

                        for item in items:
                            if len(rows) >= needed:
                                break
                            ds_id = item.get("id") or item.get("modelId") or ""
                            if not ds_id:
                                continue
                            url = f"https://huggingface.co/datasets/{ds_id}"
                            if url in seen_urls:
                                continue
                            seen_urls.add(url)

                            desc = (item.get("description") or "").strip()[:300]
                            if not desc:
                                desc = f"HuggingFace dataset: {ds_id}"

                            # Tags from the API response
                            hf_tags: list[str] = item.get("tags") or []
                            lic_raw = next(
                                (t.replace("license:", "") for t in hf_tags
                                 if t.startswith("license:")), None)
                            lic = _map_license(lic_raw)

                            country, _ = _infer_country(ds_id, desc, hf_tags, signals)
                            if not country:
                                country = primary

                            rows.append(make_row(
                                name=ds_id,
                                subdomain=subdomain,
                                country=country,
                                description=desc,
                                url=url,
                                field=config.field,
                                category="Dataset",
                                fmt="JSONL",
                                license_=lic,
                                author="huggingface.co",
                                tags=tags_str,
                                note=f"HuggingFace dataset – kw:{kw}",
                            ))

                        if len(items) < 100:
                            break
                        offset += 100
                        time.sleep(0.2)   # polite rate-limiting

        return rows
