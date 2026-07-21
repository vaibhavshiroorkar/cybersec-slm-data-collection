#!/usr/bin/env python3
"""Sourcing entry point — a thin re-export of the one engine.

The sourcing stage is driven by a single engine
(:func:`cybersec_slm.sourcing.orchestrator.source`) configured by one per-profile
``sourcing.yaml`` (:mod:`cybersec_slm.sourcing.config`). This module keeps ``source``
importable at the historical ``sourcing.run`` location for the CLI and dashboard.

The three earlier engines this replaced — the legacy SearXNG ``discover``, the
``harvest`` bulk driver, and the ``hybrid`` coordinator — are gone; ``ckan`` and the
other bulk backends are now first-class backends of the one engine, so ``--harvest``
is redundant.
"""

from __future__ import annotations

from ..core import LOGS  # re-exported so tests can monkeypatch the log dir here
from .orchestrator import source

__all__ = ["source", "LOGS"]
