#!/usr/bin/env python3
"""What an EDA fix round should do.

The EDA gate reports that the corpus is skewed and then stops, leaving the
operator to work out which sub-domains are starved, how many sources to look
for, and which stages to re-run over just those. This module makes those
decisions; :mod:`.run_fix` carries them out in a loop.

The fix balances by *adding* data, never by deleting it. The gate's other lever,
``cleaning.balance.apply_cap``, randomly downsamples data/clean in place (it
silently deleted ~70k cleaned records on a real build, which is why
``EDA_AUTO_REBALANCE`` defaults off). Over-representation is only ever a
warning, so nothing is blocked by leaving those records alone; a starved
sub-domain is fixed by sourcing for it, which is what the gate's own feedback
recommends.

Pure and side-effect-free, like the other planners in :mod:`.control`, so the
decisions are unit-tested without starting a pipeline.
"""

from __future__ import annotations

from ..eda import config as eda_config
from . import control, settings_store

# How many source -> ingest -> clean rounds a fix run will attempt before giving
# up. Each round is expensive (discovery plus fetching plus cleaning), and a
# corpus that has not moved toward balance in this many rounds is short of
# available sources rather than short of rounds.
DEFAULT_ROUNDS = 4

# How many catalog rows a round asks for beyond what a starved sub-domain already
# has, when it is already level with the best-covered one. Without a step the
# fill would be handed a target it already meets and would discover nothing.
DEFAULT_ROW_STEP = 25

# A sub-domain holding less than this fraction of the average sub-domain's
# records is starved. Mirrors the gate's own feedback rule
# (``eda.pipeline._generate_feedback``) so the fix agrees with what the page says.
UNDER_FRACTION = 0.25


def _metrics(report: dict) -> dict:
    """The report's operative metrics.

    A run that capped over-represented sub-domains describes its real end state
    in ``metrics_after_rebalance``; ``metrics`` is then the *pre*-cap picture and
    would send a fix round chasing an imbalance that no longer exists.
    """
    report = report or {}
    return (report.get("metrics_after_rebalance")
            or report.get("metrics") or {})


def lacking(report: dict) -> list[str]:
    """Sub-domains that are short of data, worst-case first by name order.

    Prefers the gate's own ``feedback.under_represented``: it is the same list the
    EDA page shows, so a fix run cannot disagree with the advice on screen. Falls
    back to recomputing from metrics for a report written before feedback existed.
    """
    fb = (report or {}).get("feedback") or {}
    under = fb.get("under_represented")
    if under:
        return sorted({e["subdomain"] for e in under if e.get("subdomain")})

    m = _metrics(report)
    subs = m.get("subdomains") or {}
    if not subs:
        return []
    dist = m.get("subdomain_distribution") or {}
    avg = sum(subs.values()) / len(subs)
    return sorted(s for s, n in subs.items()
                  if n < avg * UNDER_FRACTION
                  or dist.get(s, 0.0) < eda_config.MIN_SUBDOMAIN_SHARE)


def is_balanced(report: dict) -> bool:
    """True when no sub-domain is starved and the spread itself is acceptable.

    Both halves matter: every sub-domain can clear the volume and share bars while
    the corpus is still lopsided, which is what topic CV measures. An empty report
    is not balanced - no evidence is not evidence of balance.
    """
    m = _metrics(report)
    if not (m.get("subdomains") or {}):
        return False
    if lacking(report):
        return False
    return float(m.get("topic_cv") or 0.0) <= eda_config.MAX_TOPIC_CV


def row_target(counts: dict[str, int], domains: list[str],
               step: int = DEFAULT_ROW_STEP) -> int:
    """Catalog rows per sub-domain a round should fill up to.

    ``counts`` is commercial-valid rows per Sub-Domain
    (:func:`sourcing.sheet.valid_counts_by_subdomain`). The aim is parity with the
    best-covered sub-domain, because that is what balance means here. When the
    starved ones are already level with it, the target is raised a step so the
    fill has a deficit to work on rather than being handed a target it already
    meets and discovering nothing.
    """
    if not domains:
        return 0
    here = max((counts.get(d, 0) for d in domains), default=0)
    best = max(counts.values(), default=0)
    return max(best, here + step)


def plan_round(domains: list[str], target: int,
               settings: dict | None = None) -> list[list[str]]:
    """The stages one fix round runs, as argv lists for :func:`cli.main`.

    Source, then ingest, then clean, each scoped to ``domains`` so a round costs
    only the starved sub-domains rather than the whole corpus. Ingest and clean
    resume: a *selective* fresh run wipes ``data/raw/<domain>/`` and
    ``data/clean/<domain>/`` before working, which would delete the very corpus
    the round exists to grow.
    """
    over = dict(settings or {})
    doms = list(domains)
    src = {**settings_store.get_stage("source"), **over,
           "domains": doms, "target_per_domain": target}
    ing = {**settings_store.get_stage("ingest"), **over, "domains": doms}
    cln = {**settings_store.get_stage("clean"), **over, "domains": doms}
    return [
        control.stage_argv("source", settings=src),
        control.stage_argv("ingest", resume=True, settings=ing),
        control.stage_argv("clean", resume=True, settings=cln),
    ]
