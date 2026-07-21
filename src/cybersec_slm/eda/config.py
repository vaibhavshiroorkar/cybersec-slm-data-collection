#!/usr/bin/env python3
"""EDA sufficiency-gate thresholds (env-overridable).

The gate turns EDA from a passive report into an enforcement point (threat model
Stage 3 "Unacted Analytical Gaps"): a *blocker* violation stops the run so the
named owner investigates / loops back to ingestion; a *warning* is logged and
tracked across runs. Defaults are deliberately permissive so a small local build
passes; tune per environment with the env vars below.
"""

from __future__ import annotations

import os


def _i(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _f(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


MIN_TOTAL_RECORDS = _i("EDA_MIN_TOTAL", 50)              # blocker below this
MIN_RECORDS_PER_SUBDOMAIN = _i("EDA_MIN_PER_SUBDOMAIN", 5)   # warning below this
MAX_SOURCE_SHARE = _f("EDA_MAX_SOURCE_SHARE", 0.60)     # concentration ceiling (warning)
MAX_DRIFT = _f("EDA_MAX_DRIFT", 0.25)                    # max subdomain-share delta vs prev run
MAX_DUP_RATE = _f("EDA_MAX_DUP_RATE", 0.40)             # warning above this
MIN_AVG_TOKENS = _f("EDA_MIN_AVG_TOKENS", 5.0)          # warning below this
OWNER = os.environ.get("EDA_OWNER", "data-collection-team")

# ── v2: topic-balance thresholds ─────────────────────────────────────────────
# Coefficient of variation across subdomain record counts.  A CV above this
# signals that the corpus is heavily skewed toward a few subdomains (warning).
MAX_TOPIC_CV = _f("EDA_MAX_TOPIC_CV", 1.5)

# Any subdomain below this share of total records triggers a warning — below 1%
# means the subdomain is effectively absent from the training signal. (A warning,
# not a blocker: the only hard blocker is total volume; see evaluate_gate.)
MIN_SUBDOMAIN_SHARE = _f("EDA_MIN_SUBDOMAIN_SHARE", 0.01)

# When True, the deep EDA pass automatically caps over-represented subdomains
# using ``cleaning.balance.apply_cap`` and re-validates.
def _bool_env(name: str, default: bool) -> bool:
    env = os.environ.get(name)
    if env is None:
        return default
    return env.strip().lower() in ("1", "true", "yes", "on")


# Off by default: auto-rebalance uses ``apply_cap``, which RANDOMLY downsamples
# over-represented subdomains and rewrites data/clean/ in place — on a real build
# that silently deleted ~70k already-cleaned records to hit the topic-CV target.
# Over-representation is only ever a *warning* (never a blocker), so leaving the
# data in place cannot halt the run; the gate still reports the imbalance and the
# feedback section recommends `clean balance --cap N`. Opt back in with
# ``EDA_AUTO_REBALANCE=1`` when you deliberately want the corpus trimmed.
AUTO_REBALANCE = _bool_env("EDA_AUTO_REBALANCE", False)
