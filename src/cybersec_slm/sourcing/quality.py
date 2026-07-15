#!/usr/bin/env python3
"""Cheap quality filter for discovery results, run before enrichment.

Discovery pulls whatever SearXNG returns; a lot of it is social/video/junk or a
listing/search/tag landing page rather than an actual dataset, repo, or document.
Enrichment (the license + metadata fetch) is the expensive step, so :func:`passes`
drops the obvious non-sources up front - by junk host and by listing-page URL shape
- and keeps everything else. It never fetches; it only inspects the result's link,
so it is pure and unit-testable.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

# Social / video / Q&A / commerce hosts that are never a training source.
_JUNK_HOSTS = {
    "pinterest.com", "facebook.com", "fb.com", "twitter.com", "x.com",
    "youtube.com", "youtu.be", "reddit.com", "instagram.com", "tiktok.com",
    "linkedin.com", "quora.com",
}

# Path segments that mark a listing / tag / search page, not a single source.
# Applied even on otherwise-licensable hosts (e.g. github.com/search, /topics).
_LISTING_SEGMENTS = {
    "search", "tag", "tags", "topic", "topics", "category", "categories",
    "label", "labels",
}


def _host(netloc: str) -> str:
    """Bare, lowercased host without credentials, port, or a ``www.`` prefix."""
    return netloc.split("@")[-1].split(":")[0].lower().removeprefix("www.")


def _is_junk_host(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in _JUNK_HOSTS)


def passes(result) -> bool:
    """Return True when a search ``result`` is worth enriching (keep), else False.

    Default-keep: a link is dropped only when its host is a known junk host or its
    URL is shaped like a listing/search/tag page (a path segment such as
    ``search``/``tags``/``topics`` or a bare ``?q=`` query). Empty or host-less
    links are dropped.
    """
    link = (getattr(result, "link", "") or "").strip()
    if not link:
        return False
    p = urlparse(link if "://" in link else "//" + link, scheme="https")
    host = _host(p.netloc)
    if not host or "." not in host:
        return False
    if _is_junk_host(host):
        return False
    segments = [s for s in p.path.lower().split("/") if s]
    if any(s in _LISTING_SEGMENTS for s in segments):
        return False
    if "q" in parse_qs(p.query):
        return False
    return True
