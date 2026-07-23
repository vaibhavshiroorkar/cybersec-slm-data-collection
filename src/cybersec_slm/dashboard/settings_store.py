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

Settings are **per profile**: the cybersecurity corpus and the banking-compliance
one want different worker counts, caps, and sourcing knobs, so switching profiles
switches the whole settings set with it (see
:mod:`cybersec_slm.sourcing.profiles`).

On-disk shape::

    {"profiles": {"ubi":      {"ingest": {"workers": 8}, "clean": {...}},
                  "cybersec": {"ingest": {"workers": 4}, ...}}}

A legacy flat file (``{"ingest": {...}, ...}``, written before profiles existed)
is read as belonging to the active profile and re-nested on the next write, so an
existing install keeps its saved settings rather than silently reverting to
defaults.

:func:`load` and :func:`get_stage` return the *active profile's* map, so callers
that predate profiles keep working unchanged; :func:`load_file` exposes the raw
file for anything that needs every profile at once.
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


# Top-level key holding the per-profile settings maps.
_PROFILES_KEY = "profiles"


def settings_path(path: str | None = None) -> str:
    return path or os.path.join(core.data_root(), FILE_NAME)


def _active_profile() -> str:
    from ..sourcing import profiles
    return profiles.active()


def load_file(path: str | None = None) -> dict:
    """The raw settings file (``{"profiles": {name: {stage: {...}}}}``); {} if absent."""
    p = settings_path(path)
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _split(data: dict) -> tuple[dict, dict]:
    """``(profiles_map, legacy_flat_map)`` from a raw file of either shape."""
    nested = data.get(_PROFILES_KEY)
    if isinstance(nested, dict):
        return {k: v for k, v in nested.items() if isinstance(v, dict)}, {}
    # Legacy flat file: every top-level dict value is a stage's settings.
    legacy = {k: v for k, v in data.items() if isinstance(v, dict)}
    return {}, legacy


def load(path: str | None = None, *, profile: str | None = None) -> dict:
    """The active (or named) profile's settings map (``{stage: {key: value}}``).

    A legacy flat file is attributed to the active profile — see the module
    docstring.
    """
    name = profile or _active_profile()
    nested, legacy = _split(load_file(path))
    if nested:
        val = nested.get(name)
        return dict(val) if isinstance(val, dict) else {}
    return dict(legacy) if name == _active_profile() else {}


# Settings the dashboard no longer offers, stripped on read so a value saved
# before its toggle was retired cannot keep steering runs from a file nobody
# opens. This is not hypothetical: pipeline_settings.json carried
# ``all.no_crawler: true``, which skipped every website source of every full run.
#
#   resume      -- a property of a launch, not of a stage. Start and Resume each
#                  pass it; a saved true silently outvoted the button pressed.
#   no_enrich   -- enrichment resolves License, which the ingestion gate reads. A
#                  row discovered without it is unusable until a backfill.
#   no_crawler  -- crawling is how a website row is fetched at all, so off does
#                  not change the run, it just drops those sources.
RETIRED_KEYS: frozenset[str] = frozenset({"resume", "no_enrich", "no_crawler"})


def get_stage(stage: str, path: str | None = None, *,
              profile: str | None = None) -> dict:
    """Saved settings for one stage of the active (or named) profile.

    Retired keys (:data:`RETIRED_KEYS`) are dropped: they have no widget any more,
    so a leftover value would be configuration nobody can see or unset.
    """
    val = load(path, profile=profile).get(stage)
    if not isinstance(val, dict):
        return {}
    return {k: v for k, v in val.items() if k not in RETIRED_KEYS}


def save_stage(stage: str, settings: dict, path: str | None = None, *,
               profile: str | None = None) -> str:
    """Persist ``settings`` as ``stage``'s defaults for one profile; return the path.

    Writing always emits the nested shape, which is what migrates a legacy flat
    file: its stages are carried over as the active profile's, then the new value
    is applied on top.
    """
    name = profile or _active_profile()
    p = settings_path(path)
    nested, legacy = _split(load_file(path))
    if legacy and not nested:
        nested = {_active_profile(): legacy}
    stages = dict(nested.get(name) or {})
    stages[stage] = dict(settings or {})
    nested[name] = stages

    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    tmp = f"{p}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({_PROFILES_KEY: nested}, f, indent=2)
    os.replace(tmp, p)
    return p


def merged_all(path: str | None = None, *,
               profile: str | None = None) -> dict:
    """Saved settings merged for a full ``all`` run.

    Combines every stage's saved settings (ingest/clean/eda/schema) plus any saved
    under ``all``; ``build_command('all', ...)`` later drops any flag ``all`` does
    not accept, so per-stage-only flags (e.g. ``domains``) fall away harmlessly.
    """
    data = load(path, profile=profile)
    out: dict = {}
    for stage in _ALL_FEED_ORDER:
        val = data.get(stage)
        if isinstance(val, dict):
            out.update(val)
    return out

