#!/usr/bin/env python3
"""Persistent per-stage advanced settings for the dashboard.

Advanced settings (worker count, caps, crawler on/off, sourcing knobs, ...) are
saved to a small JSON file so they survive dashboard restarts and, crucially, so a
value configured on one page drives **both** that stage's individual run and the
full pipeline run launched from the Overview page.

The file lives at the data root (``pipeline_settings.json``), alongside ``data/``
and ``logs/`` but outside them, so a Reset (which wipes ``data/`` and ``logs/``)
never clears saved settings. Streamlit-free and side-effect-light, so it is
unit-testable directly.

Shape::

    {"ingest": {"workers": 8, ...}, "clean": {...}, "source": {...}, "all": {...}}
"""

from __future__ import annotations

import json
import os

from .. import core

FILE_NAME = "pipeline_settings.json"

# Stages whose saved settings feed a full ``all`` run, in increasing precedence
# (``all`` last so an explicit Overview save wins over a per-stage save). Used only
# to seed the Overview override panel - the full run itself reads each stage's saved
# settings directly (control.build_full_plan), so cross-stage flag collisions in this
# flat merge do not affect the actual per-stage commands.
_ALL_FEED_ORDER = ("schema", "eda", "clean", "ingest", "source", "all")


def settings_path(path: str | None = None) -> str:
    return path or os.path.join(core.data_root(), FILE_NAME)


def load(path: str | None = None) -> dict:
    """Load the whole settings map (``{stage: {key: value}}``); {} if absent."""
    p = settings_path(path)
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def get_stage(stage: str, path: str | None = None) -> dict:
    """Saved settings for one stage (empty dict if none)."""
    val = load(path).get(stage)
    return dict(val) if isinstance(val, dict) else {}


def save_stage(stage: str, settings: dict, path: str | None = None) -> str:
    """Persist ``settings`` as the saved defaults for ``stage``; return the path."""
    p = settings_path(path)
    data = load(path)
    data[stage] = dict(settings or {})
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    tmp = f"{p}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, p)
    return p


def merged_all(path: str | None = None) -> dict:
    """Saved settings merged for a full ``all`` run.

    Combines every stage's saved settings (ingest/clean/eda/schema) plus any saved
    under ``all``; ``build_command('all', ...)`` later drops any flag ``all`` does
    not accept, so per-stage-only flags (e.g. ``domains``) fall away harmlessly.
    """
    data = load(path)
    out: dict = {}
    for stage in _ALL_FEED_ORDER:
        val = data.get(stage)
        if isinstance(val, dict):
            out.update(val)
    return out
