#!/usr/bin/env python3
"""Canonical five-stage pipeline model - the single source of truth for stages.

The pipeline is five physically separate steps, in order:

    1. source  - discover / curate sources into sources/Sources.csv
    2. ingest  - fetch raw data from those sources -> data/raw/
    3. clean   - clean records + cross-source dedup -> data/clean/
    4. eda      - the sufficiency gate over data/clean/
    5. schema  - normalize onto the canonical schema -> data/final/dataset.jsonl

The CLI, the dashboard control plane, and the dashboard phase parser all read
this module instead of each keeping their own private list of stages. `markers`
are substrings that, when present in a pipeline log, mean the run has reached
that stage; `phase_from_log` uses them to report the furthest-along stage.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Stage:
    """One pipeline stage: its key, human label, CLI command, and log markers."""

    key: str
    label: str
    cli: str
    markers: tuple[str, ...]


# Ordered spine of the pipeline. Order is progression order (source first,
# schema last); `phase_from_log` treats a later entry as "further along".
STAGES: list[Stage] = [
    Stage("source", "Sourcing", "source",
          ("source:", "discovered", "sourcing:")),
    Stage("ingest", "Ingest", "ingest",
          ("ingest:", "=== source:", "fetched")),
    Stage("clean", "Clean", "clean",
          ("clean:", "cleaned ", "final global dedup", "final dedup:")),
    Stage("eda", "EDA gate", "eda",
          ("deep global EDA", "eda: scanning", "eda: total=", "auto-rebalanc",
           "apply_cap", "source-cap", "eda FEEDBACK", "apply_source_cap")),
    Stage("schema", "Schema", "normalize",
          ("schema normalization", "normalize:", "provenance manifest",
           "handoff-ready corpus")),
]

_BY_KEY = {s.key: s for s in STAGES}


def stage_keys() -> list[str]:
    """The five stage keys, in pipeline order."""
    return [s.key for s in STAGES]


def get_stage(key: str) -> Stage:
    """Look up a stage by key (raises KeyError for an unknown key)."""
    return _BY_KEY[key]


def phase_from_log(lines: list[str]) -> str:
    """Furthest-along stage key whose marker appears in `lines`.

    Returns ``"unknown"`` when there are no lines at all, ``"starting"`` when
    lines exist but none match a stage marker, else the key of the furthest
    stage reached (a later stage in ``STAGES`` supersedes an earlier one).
    """
    if not lines:
        return "unknown"
    best = -1
    for idx, stage in enumerate(STAGES):
        if any(any(m in ln for m in stage.markers) for ln in lines):
            best = idx
    if best < 0:
        return "starting"
    return STAGES[best].key
