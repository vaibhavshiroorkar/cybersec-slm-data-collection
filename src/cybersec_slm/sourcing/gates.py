#!/usr/bin/env python3
"""The single accept/reject gate every sourcing candidate passes through.

This is the one place that decides whether a discovered candidate earns a place in
the catalog, and it is what resolves the contradiction the old two-engine setup
carried: the hybrid engine *trusted* regulator hosts on host-reputation while the
legacy engine *barred* them on legal scope, and the catalog ended up full of rows
that could never be ingested. Here every candidate from every backend goes through
the *same* ordered checks, so a restricted host can never be admitted on any other
signal.

Ordered checks (first failure wins; see :func:`evaluate`):

1. **Host/shape** — :func:`cybersec_slm.sourcing.quality.classify` drops bad links,
   junk (social/video) hosts, **restricted** (licensing-barred) hosts, and
   listing/search/tag pages. ``sourcing.yaml``'s ``restricted_hosts`` extend the
   taxonomy's, applied here too, so restricted always wins.
2. **Off-topic** — a configured off-topic signal word in the text drops it.
3. **License integrity** — :func:`cybersec_slm.ingestion.license_gate.license_verdict`
   over the row's real (backend-metadata, then optionally enriched) license.
   ``blocked`` is dropped. A *first-party / owner-authorized* stamp is honoured only
   when the profile opts in (``allow_owned_first_party``); otherwise it is treated
   as ``unknown``, because for a training corpus a self-asserted first-party claim
   is not a real license. **No license is ever fabricated here or in a backend.**
4. **Liveness** — a non-API URL is HTTP-checked; a dead link is dropped.

The functions are pure (bar the liveness HTTP call, which is injectable) so each
reject reason is unit-testable in isolation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..ingestion.license_gate import license_verdict
from . import quality
from .quality import KEEP, RESTRICTED_HOST
from .quality import WRONG_COUNTRY as _WRONG_COUNTRY

# Markers of a first-party / owner-authorized license stamp (see
# ingestion.license_gate's allow set and sourcing.taxonomies.OWNED_LICENSE). Kept in
# sync with that gate's first-party clause.
_FIRST_PARTY = re.compile(r"first[- ]party|owner[- ]authori[sz]ed", re.IGNORECASE)

# Terminal gate stages, in check order. Stable strings for logs/tests.
BAD = "bad link"
JUNK = "junk host"
RESTRICTED = RESTRICTED_HOST
WRONG_COUNTRY = _WRONG_COUNTRY
LISTING = "listing page"
OFF_TOPIC = "off-topic signal"
LOW_RELEVANCE = "low relevance"
LICENSE_BLOCKED = "license blocked"
DEAD = "dead link"
KEPT = "kept"

# Note text stamped on a row admitted from a licensing-restricted host under the
# "flag" policy, so the reason travels with the row into the catalog.
RESTRICTED_NOTE = "RESTRICTED HOST — license unconfirmed, ingestion must verify"


def is_first_party(license_str: str | None) -> bool:
    """True when ``license_str`` is a first-party / owner-authorized stamp."""
    return bool(_FIRST_PARTY.search(license_str or ""))


@dataclass
class GateResult:
    """Outcome of the gate for one candidate."""

    kept: bool
    stage: str            # one of the terminal-stage constants above
    detail: str = ""      # human sentence for a log line
    host: str = ""        # bare host, for the restricted-host tally
    verdict: str = ""     # license verdict when the license stage ran ("ok"/"unknown"/"blocked")


def _extra_restricted(host: str, cfg) -> str:
    """Reason ``host`` is restricted by ``cfg.restricted_hosts`` beyond the taxonomy."""
    h = (host or "").strip().lower().removeprefix("www.")
    for dom, reason in (cfg.restricted_hosts or {}).items():
        d = dom.strip().lower().removeprefix("www.")
        if h == d or h.endswith("." + d):
            return reason
    return ""


def classify_host(result, cfg) -> GateResult | None:
    """Host/shape check (check 1).

    Returns ``None`` for an ordinary keep, a ``kept=False`` :class:`GateResult` for
    a drop, or — for a licensing-restricted host under ``restricted_policy: "flag"``
    — a ``kept=True`` result carrying the restriction reason. Flagging is *not* an
    assertion that the content is usable: the caller blanks the row's License and
    records the reason, leaving the verdict to ingestion's deep per-URL check.
    A restricted *site* is not a restricted *page* — rbi.org.in's prose is
    all-rights-reserved while its RSS feed reduces to an allowable metadata index,
    and dropping the host at sourcing time made that distinction unreachable.
    """
    category, detail = quality.classify(result)
    host = quality.reject_host(result)
    # sourcing.yaml may restrict hosts the taxonomy does not; merge both sources so
    # the policy applies uniformly to either origin.
    if category == KEEP:
        reason = _extra_restricted(host, cfg)
        if reason:
            category, detail = RESTRICTED, f"{host}: {reason}"
    if category == KEEP:
        return None
    if category == RESTRICTED and getattr(cfg, "restricted_policy", "drop") == "flag":
        return GateResult(True, RESTRICTED, detail, host=host)
    return GateResult(False, category, detail, host=host)


def country_ok(row: dict, cfg) -> bool:
    """Whether ``row``'s classified Country satisfies ``cfg.country_filter``.

    No filter configured means every country passes. A row with no Country value at
    all is *kept*: a blank is "unclassified", not "wrong", and dropping it would
    silently discard sources whose geography the classifier simply could not read.
    """
    want = (getattr(cfg, "country_filter", None) or "").strip()
    if not want:
        return True
    got = str(row.get("Country") or "").strip()
    return not got or got.casefold() == want.casefold()


def off_topic(text: str, cfg) -> bool:
    """True when ``text`` carries a configured off-topic signal word."""
    signals = cfg.quality.off_topic_signals if cfg and cfg.quality else []
    if not signals:
        return False
    low = (text or "").lower()
    return any(s in low for s in signals)


def keyword_relevance(text: str, terms, cfg) -> tuple[bool, int]:
    """``(passes, hits)`` — how many of the sub-domain's vocab terms ``text`` carries.

    The backends are keyword-scoped but not keyword-*bound*: Zenodo and GitHub
    happily answer a "money laundering" query with a beetle taxonomy record or an
    unrelated repo. Requiring at least ``quality.min_keyword_hits`` of the
    sub-domain's distinctive vocab terms (``aml``, ``kyc``, ``money laundering``,
    ...) in the title/description is a cheap topicality floor.

    Substring matching, matching :func:`cybersec_slm.sourcing.classify._score` — the
    vocab terms are already short and distinctive, and word-boundary matching would
    miss legitimate compounds ("anti-money-laundering"). ``min_keyword_hits <= 0``
    disables the check entirely (the default), so it is opt-in per profile.
    """
    need = cfg.quality.min_keyword_hits if (cfg and cfg.quality) else 0
    if need <= 0:
        return True, 0
    low = (text or "").lower()
    hits = sum(1 for t in terms if t and str(t).lower() in low)
    return hits >= need, hits


def resolve_license(row: dict, cfg, enricher) -> str:
    """Return the row's license verdict after real-metadata + optional enrichment.

    Fills a blank/unknown license via ``enricher`` when ``cfg.enrich_unknown`` and an
    enricher is provided (enrichment reads *real* source metadata only). A first-party
    stamp is downgraded to ``unknown`` unless the profile allows it, so a self-asserted
    first-party claim cannot pass as a real license. Never invents a license string.
    """
    lic = str(row.get("License") or "").strip()
    verdict = license_verdict(lic)

    if verdict == "unknown" and cfg.enrich_unknown and enricher is not None:
        enricher.enrich(row)                       # fills License from real metadata / owned stamp
        lic = str(row.get("License") or "").strip()
        verdict = license_verdict(lic)

    if verdict == "ok" and is_first_party(lic) and not cfg.allow_owned_first_party:
        # A first-party/owner-authorized stamp is the profile asserting it owns the
        # host; for a strict corpus that is not a real license. Blank it and treat as
        # unknown so it never counts as commercial-valid without opt-in.
        row["License"] = ""
        verdict = "unknown"
    return verdict


def is_live(url: str, timeout: float = 6.0, _head=None, _get=None) -> bool:
    """Best-effort liveness: HEAD (GET fallback on 405). Any error counts as dead.

    ``_head``/``_get`` are injectable for tests; default to ``httpx``.
    """
    try:
        import httpx
        head = _head or (lambda u: httpx.head(u, timeout=timeout, follow_redirects=True))
        get = _get or (lambda u: httpx.get(u, timeout=timeout, follow_redirects=True))
        resp = head(url)
        if getattr(resp, "status_code", 599) == 405:
            resp = get(url)
        return getattr(resp, "status_code", 599) < 400
    except Exception:
        return False
