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
MAX_SOURCE_SHARE = _f("EDA_MAX_SOURCE_SHARE", 0.60)     # concentration ceiling (blocker)
MAX_DRIFT = _f("EDA_MAX_DRIFT", 0.25)                    # max subdomain-share delta vs prev run
MAX_DUP_RATE = _f("EDA_MAX_DUP_RATE", 0.40)             # warning above this
MIN_AVG_TOKENS = _f("EDA_MIN_AVG_TOKENS", 5.0)          # warning below this
OWNER = os.environ.get("EDA_OWNER", "data-collection-team")
