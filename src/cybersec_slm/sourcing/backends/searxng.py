#!/usr/bin/env python3
"""SearXNG meta-search backend — the last-resort, license-unknown discoverer.

Wraps :func:`cybersec_slm.sourcing.search.searxng_search`. SearXNG returns only a
link/title/snippet with no license metadata, so every candidate's license is blank
(Unknown) and left to the engine's enrich step and the ingestion gate. This is why
it is marked ``last_resort`` in config: broad reach, lowest signal. It degrades to
``[]`` when the instance is unreachable rather than aborting a run.
"""

from __future__ import annotations

from ..search import SearchError, searxng_search
from .base import Backend, Candidate


class SearXNGBackend(Backend):
    name = "searxng"

    def search(self, subdomain, keyword, limit, cfg) -> list[Candidate]:
        bc = cfg.backends.get(self.name)
        if not bc:
            return []
        limit = min(limit, bc.per_keyword_limit)
        engines = bc.engines or None
        base_url = bc.url or None
        out: list[Candidate] = []
        page = 1
        try:
            while len(out) < limit and page <= 4:
                try:
                    results = searxng_search(keyword, url=base_url, num=limit,
                                             pageno=page, engines=engines)
                except SearchError:
                    break
                if not results:
                    break
                for res in results:
                    if len(out) >= limit:
                        break
                    out.append(Candidate(
                        subdomain=subdomain, result=res, backend=self.name,
                        license="",   # SearXNG carries no license; enrich/gate decide
                        note=f"SearXNG – kw:{keyword} – page:{page}"))
                page += 1
        except Exception:
            pass
        return out
