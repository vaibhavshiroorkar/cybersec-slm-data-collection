#!/usr/bin/env python3
"""arXiv OpenSearch backend — license read from the entry, blank when absent.

``GET http://export.arxiv.org/api/query``. The Atom feed does not reliably carry a
per-paper license, and arXiv's default submission license is *not* commercial for
older papers, so this backend does NOT stamp a blanket ``CC BY``. It reads an
explicit ``<link rel="license">`` when present and otherwise leaves the license
blank for the engine's enrich step (which can detect it from the abstract page).
"""

from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from urllib.parse import quote_plus

import httpx

from ..search import Result
from .base import Backend, Candidate

ARXIV_API = "http://export.arxiv.org/api/query"
NS = {"atom": "http://www.w3.org/2005/Atom"}

# SPDX-ish spelling for the CC licenses arXiv links carry as a URL.
_CC_URL_MAP = {
    "creativecommons.org/licenses/by/4.0": "CC BY 4.0",
    "creativecommons.org/licenses/by-sa/4.0": "CC BY-SA 4.0",
    "creativecommons.org/licenses/by-nc-sa/4.0": "CC BY-NC-SA 4.0",
    "creativecommons.org/licenses/by-nc/4.0": "CC BY-NC 4.0",
    "creativecommons.org/publicdomain/zero/1.0": "CC0 1.0",
}


def _text(el, tag: str) -> str:
    child = el.find(f"atom:{tag}", NS)
    return (child.text or "").strip() if child is not None else ""


def _license_from_links(entry) -> str:
    for lnk in entry.findall("atom:link", NS):
        if lnk.get("rel") == "license":
            href = (lnk.get("href") or "").lower().rstrip("/")
            for frag, name in _CC_URL_MAP.items():
                if frag in href:
                    return name
    return ""


class ArXivBackend(Backend):
    name = "arxiv"

    def search(self, subdomain, keyword, limit, cfg) -> list[Candidate]:
        bc = cfg.backends.get(self.name)
        limit = min(limit, bc.per_keyword_limit if bc else limit)
        out: list[Candidate] = []
        start = 0
        try:
            with httpx.Client(timeout=(bc.timeout if bc else 15.0), follow_redirects=True) as client:
                while len(out) < limit:
                    batch = min(100, limit - start)
                    if batch <= 0:
                        break
                    resp = client.get(ARXIV_API, params={
                        "search_query": f"all:{quote_plus(keyword)}",
                        "start": start, "max_results": batch,
                        "sortBy": "relevance", "sortOrder": "descending"})
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
                        if len(out) >= limit:
                            break
                        abs_url = pdf_url = ""
                        for lnk in entry.findall("atom:link", NS):
                            if lnk.get("type") == "text/html" or lnk.get("rel") == "alternate":
                                abs_url = lnk.get("href", "")
                            elif lnk.get("type") == "application/pdf":
                                pdf_url = lnk.get("href", "")
                        url = abs_url or pdf_url
                        if not url:
                            continue
                        title = _text(entry, "title").replace("\n", " ")
                        summary = _text(entry, "summary").replace("\n", " ")[:300]
                        published = _text(entry, "published")[:10]
                        out.append(Candidate(
                            subdomain=subdomain,
                            result=Result(title=title[:80], link=url, snippet=summary,
                                          display_link="arxiv.org"),
                            backend=self.name, license=_license_from_links(entry),
                            author="arxiv.org", last_updated=published,
                            category="Document", fmt="PDF",
                            note=f"arXiv paper – published:{published} – kw:{keyword}"))
                    if len(entries) < batch:
                        break
                    start += batch
                    time.sleep(3.0)   # arXiv asks for 1 req / 3s
        except httpx.HTTPError:
            pass
        return out
