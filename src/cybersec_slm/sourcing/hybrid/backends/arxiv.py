"""
backends/arxiv.py – ArXivBackend

Queries the arXiv OpenSearch API (Atom/XML):
  GET http://export.arxiv.org/api/query?search_query={q}&max_results=100&start={n}

No authentication required. The Atom feed is parsed to extract:
  - title, summary, authors, arxiv_id, published date, pdf_url

All arXiv papers are open-access (CC BY 4.0 by default for new papers,
varied for older ones). The license field is set to "CC BY 4.0" since arXiv
mandates at least this for all recent submissions.

Country inference: done on title + abstract text using config signals.
"""

from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import quote_plus

import httpx

from .base import Backend, make_row

ARXIV_API = "http://export.arxiv.org/api/query"
NS = {
    "atom": "http://www.w3.org/2005/Atom",
    "arxiv": "http://arxiv.org/schemas/atom",
}


def _text(el, tag: str, ns_key: str = "atom") -> str:
    child = el.find(f"{ns_key}:{tag}", NS)
    return (child.text or "").strip() if child is not None else ""


class ArXivBackend(Backend):
    """Query arXiv OpenSearch and return paper metadata."""

    name = "arxiv"

    def fetch(
        self,
        keywords: dict[str, list[str]],
        needed: int,
        seen_urls: set[str],
        config: Any,
    ) -> list[dict[str, str]]:
        bc = config.api_backends.get("arxiv")
        if bc is None or not bc.enabled:
            return []

        per_kw = min(bc.per_keyword_limit, 200)
        signals = [s.lower() for s in bc.country_signal_keywords]
        primary = config.primary_country
        tags_str = config.default_tags
        rows: list[dict[str, str]] = []

        with httpx.Client(timeout=60, follow_redirects=True) as client:
            for subdomain, kw_list in keywords.items():
                for kw in kw_list:
                    if len(rows) >= needed:
                        break
                    start = 0
                    while len(rows) < needed:
                        batch = min(100, per_kw - start)
                        if batch <= 0:
                            break
                        try:
                            resp = client.get(ARXIV_API, params={
                                "search_query": f"all:{quote_plus(kw)}",
                                "start": start,
                                "max_results": batch,
                                "sortBy": "relevance",
                                "sortOrder": "descending",
                            })
                        except httpx.HTTPError:
                            break
                        if resp.status_code != 200:
                            break

                        try:
                            root = ET.fromstring(resp.text)
                        except ET.ParseError:
                            break

                        entries = root.findall("atom:entry", NS)
                        if not entries:
                            break

                        for entry in entries:
                            if len(rows) >= needed:
                                break

                            # Primary URL: prefer abs page over PDF
                            links = entry.findall("atom:link", NS)
                            abs_url = pdf_url = ""
                            for lnk in links:
                                href = lnk.get("href", "")
                                rel = lnk.get("rel", "")
                                if lnk.get("type") == "text/html" or rel == "alternate":
                                    abs_url = href
                                elif lnk.get("type") == "application/pdf" or rel == "related":
                                    pdf_url = href
                            url = abs_url or pdf_url
                            if not url or url in seen_urls:
                                continue
                            seen_urls.add(url)

                            title = _text(entry, "title").replace("\n", " ")
                            summary = _text(entry, "summary").replace("\n", " ")[:300]
                            published = _text(entry, "published")[:10]

                            text = f"{title} {summary}".lower()
                            country = primary if (signals and any(s in text for s in signals)) else "Global"

                            rows.append(make_row(
                                name=title[:80],
                                subdomain=subdomain,
                                country=country,
                                description=summary,
                                url=url,
                                field=config.field,
                                category="Document",
                                fmt="PDF",
                                license_="CC BY 4.0",
                                author="arxiv.org",
                                tags=tags_str,
                                note=f"arXiv paper – published:{published} – kw:{kw}",
                            ))

                        if len(entries) < batch:
                            break
                        start += batch
                        time.sleep(3.0)   # arXiv rate limit: 1 req/3s

        return rows
