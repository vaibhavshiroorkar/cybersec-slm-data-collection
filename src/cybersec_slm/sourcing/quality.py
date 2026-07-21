#!/usr/bin/env python3
"""Cheap quality filter for discovery results, run before enrichment.

Discovery pulls whatever SearXNG returns; a lot of it is social/video/junk or a
listing/search/tag landing page rather than an actual dataset, repo, or document.
Enrichment (the license + metadata fetch) is the expensive step, so :func:`passes`
drops the obvious non-sources up front - by junk host, by *restricted* host, and
by listing-page URL shape - and keeps everything else. It never fetches; it only
inspects the result's link, so it is pure and unit-testable.

The restricted-host drop is a licensing filter, not a quality one: hosts in the
active profile's ``restricted_hosts`` (for ``ubi``: regulator portals, standards
bodies, bank-owned sites) publish on-topic material under terms that forbid the
commercial reuse this corpus needs, so ``ingestion.license_gate`` would block them
at the gate regardless. Dropping them here keeps them out of the catalog entirely
rather than accumulating rows that can never be ingested. Profiles that declare no
restricted hosts (``cybersec``) are unaffected.

Every drop is *categorised* (:func:`classify`), not just decided, so the sourcing
run can report what its keywords actually pulled back — "800 hits, 600 of them
rbi.org.in" is a keyword-tuning signal that a bare pass/fail hides.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from . import keywords as kw

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

# Drop categories (the ``category`` half of :func:`classify`). Stable strings —
# the sourcing summary JSON and the dashboard's Sourcing table key on them.
KEEP = ""
BAD_LINK = "bad link"
JUNK_HOST = "junk host"
RESTRICTED_HOST = "restricted host"
LISTING_PAGE = "listing page"
# Not produced by :func:`classify` (which sees only the link): the orchestrator
# raises it once a row exists and carries a classified Country. Listed here so the
# funnel and the dashboard's drop table have a stable bucket for it.
WRONG_COUNTRY = "wrong country"

# Every category a result can be dropped for, in the order they are tested —
# which is also the order the dashboard lists them.
DROP_CATEGORIES: tuple[str, ...] = (BAD_LINK, JUNK_HOST, RESTRICTED_HOST,
                                    LISTING_PAGE, WRONG_COUNTRY)


def _host(netloc: str) -> str:
    """Bare, lowercased host without credentials, port, or a ``www.`` prefix."""
    return netloc.split("@")[-1].split(":")[0].lower().removeprefix("www.")


def _is_junk_host(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in _JUNK_HOSTS)


def classify(result) -> tuple[str, str]:
    """``(category, detail)`` for a search ``result``; ``category == KEEP`` keeps it.

    ``category`` is one of :data:`DROP_CATEGORIES` (a stable, countable bucket);
    ``detail`` is the human sentence for a log line or a tooltip. Splitting them
    lets a caller tally drops by cause while still being able to say *why* a
    specific link went.
    """
    link = (getattr(result, "link", "") or "").strip()
    if not link:
        return BAD_LINK, "empty link"
    p = urlparse(link if "://" in link else "//" + link, scheme="https")
    host = _host(p.netloc)
    if not host or "." not in host:
        return BAD_LINK, "no host in link"
    if _is_junk_host(host):
        return JUNK_HOST, f"social/video/Q&A host ({host})"
    restricted = kw.restricted_reason(host)
    if restricted:
        return RESTRICTED_HOST, f"{host}: {restricted}"
    segments = [s for s in p.path.lower().split("/") if s]
    if any(s in _LISTING_SEGMENTS for s in segments):
        return LISTING_PAGE, "listing/search/tag page, not a single source"
    if "q" in parse_qs(p.query):
        return LISTING_PAGE, "search-query URL, not a single source"
    return KEEP, ""


def reject_reason(result) -> str:
    """Why a ``result`` is dropped, or ``""`` when it should be kept."""
    return classify(result)[1]


def reject_host(result) -> str:
    """The result's bare host (``""`` when the link has none) — for per-host tallies."""
    link = (getattr(result, "link", "") or "").strip()
    if not link:
        return ""
    p = urlparse(link if "://" in link else "//" + link, scheme="https")
    return _host(p.netloc)


def passes(result) -> bool:
    """Return True when a search ``result`` is worth enriching (keep), else False.

    Default-keep: a link is dropped only when its host is a known junk host, its
    host is licensing-restricted (see the profile's ``restricted_hosts``), or its
    URL is shaped like a listing/search/tag page (a path segment such as
    ``search``/``tags``/``topics`` or a bare ``?q=`` query). Empty or host-less
    links are dropped.
    """
    return classify(result)[0] == KEEP
