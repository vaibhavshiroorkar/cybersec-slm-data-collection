#!/usr/bin/env python3
"""Dedup for the sourcing engine: against the live catalog + within one run.

A thin wrapper over :func:`cybersec_slm.sourcing.sheet.normalize_url` and
:func:`~cybersec_slm.sourcing.sheet.existing_links` so a candidate is dropped when
its URL is already in ``Sources.csv`` *or* was already emitted earlier this run.
Normalization (scheme / ``www.`` / trailing-slash / query stripped) makes "already
have it" robust to trivially-different URL spellings.
"""

from __future__ import annotations

from .sheet import existing_links, normalize_url


class Dedup:
    """Tracks every URL already known, seeding from the catalog on construction."""

    def __init__(self, csv_path: str | None):
        self._seen: set[str] = existing_links(csv_path) if csv_path else set()

    def __len__(self) -> int:
        return len(self._seen)

    def is_new(self, url: str) -> bool:
        """True when ``url`` (normalized) is neither in the catalog nor seen this run."""
        n = normalize_url(url)
        return bool(n) and n not in self._seen

    def add(self, url: str) -> None:
        n = normalize_url(url)
        if n:
            self._seen.add(n)

    def take(self, url: str) -> bool:
        """Atomically: if new, record it and return True; else return False."""
        if self.is_new(url):
            self.add(url)
            return True
        return False
