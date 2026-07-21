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

# Markers of a first-party / owner-authorized license stamp (see
# ingestion.license_gate's allow set and sourcing.taxonomies.OWNED_LICENSE). Kept in
# sync with that gate's first-party clause.
_FIRST_PARTY = re.compile(r"first[- ]party|owner[- ]authori[sz]ed", re.IGNORECASE)

# Terminal gate stages, in check order. Stable strings for logs/tests.
BAD = "bad link"
JUNK = "junk host"
RESTRICTED = RESTRICTED_HOST
LISTING = "listing page"
OFF_TOPIC = "off-topic signal"
LICENSE_BLOCKED = "license blocked"
DEAD = "dead link"
KEPT = "kept"


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
    """Host/shape drop (checks 1). Returns a drop :class:`GateResult`, or ``None``."""
    category, detail = quality.classify(result)
    host = quality.reject_host(result)
    if category != KEEP:
        return GateResult(False, category, detail, host=host)
    # sourcing.yaml may restrict hosts the taxonomy does not.
    reason = _extra_restricted(host, cfg)
    if reason:
        return GateResult(False, RESTRICTED, f"{host}: {reason}", host=host)
    return None


def off_topic(text: str, cfg) -> bool:
    """True when ``text`` carries a configured off-topic signal word."""
    signals = cfg.quality.off_topic_signals if cfg and cfg.quality else []
    if not signals:
        return False
    low = (text or "").lower()
    return any(s in low for s in signals)


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
