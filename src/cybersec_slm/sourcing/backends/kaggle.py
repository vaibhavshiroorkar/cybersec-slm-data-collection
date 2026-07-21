#!/usr/bin/env python3
"""Kaggle datasets backend — license from the dataset's ``licenseName`` field.

Uses the official ``kaggle`` client (already a pipeline dependency, used by
ingestion). Needs Kaggle credentials in the environment (``KAGGLE_USERNAME`` +
``KAGGLE_KEY``) or a ``~/.kaggle/kaggle.json``; when absent, authentication fails
and the backend degrades to ``[]`` instead of raising. ``Unknown``/``Other``
license names map to blank for the enrich step — nothing is invented.
"""

from __future__ import annotations

from ..search import Result
from .base import Backend, Candidate

_BLANK_LICENSES = {"unknown", "other", ""}


def _license(name: str) -> str:
    return "" if (name or "").strip().lower() in _BLANK_LICENSES else name.strip()


class KaggleBackend(Backend):
    name = "kaggle"

    def _api(self):
        """Return an authenticated KaggleApi, or ``None`` when creds are missing."""
        try:
            from kaggle import KaggleApi
            api = KaggleApi()
            api.authenticate()
            return api
        except Exception:
            return None

    def search(self, subdomain, keyword, limit, cfg) -> list[Candidate]:
        bc = cfg.backends.get(self.name)
        limit = min(limit, bc.per_keyword_limit if bc else limit)
        api = self._api()
        if api is None:
            return []
        out: list[Candidate] = []
        page = 1
        try:
            while len(out) < limit:
                datasets = api.dataset_list(search=keyword, page=page) or []
                if not datasets:
                    break
                for ds in datasets:
                    if len(out) >= limit:
                        break
                    ref = getattr(ds, "ref", "") or str(ds)
                    if not ref:
                        continue
                    url = getattr(ds, "url", "") or f"https://www.kaggle.com/datasets/{ref}"
                    title = getattr(ds, "title", "") or ref
                    desc = (getattr(ds, "subtitle", "") or "").strip()[:300] \
                        or f"Kaggle dataset: {title}"
                    downloads = getattr(ds, "downloadCount", None)
                    out.append(Candidate(
                        subdomain=subdomain,
                        result=Result(title=str(title)[:80], link=url, snippet=desc,
                                      display_link="kaggle.com"),
                        backend=self.name,
                        license=_license(getattr(ds, "licenseName", "")),
                        author=getattr(ds, "creatorName", "") or "kaggle.com",
                        popularity=str(downloads) if downloads else "",
                        category="Dataset",
                        note=f"Kaggle dataset – kw:{keyword}"))
                page += 1
        except Exception:
            pass
        return out
