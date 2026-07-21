#!/usr/bin/env python3
"""Load a profile's harvest spec (``harvest.yaml``), with a taxonomy fallback.

A harvest spec is the editable, persisted counterpart to search discovery's
``keywords.yaml``: it says *which* bulk backends run, with what queries, license
stamp, and quality filters. It lives at
``sources/profiles/<name>/harvest.yaml`` so it travels with the profile and
survives restarts, exactly like the keyword taxonomy. When the file is absent,
the active profile's built-in default (``Taxonomy.harvest_spec``, see
:mod:`cybersec_slm.sourcing.taxonomies`) is used, so a fresh checkout works with
no setup. A profile that defines no harvest spec (e.g. ``cybersec``, which is
search-discovery-first) returns ``{}`` and the harvest driver no-ops.

The spec is a plain dict (loaded straight from YAML) rather than a frozen
dataclass, so a user can add a backend or tweak a query by editing the file
without a code change — mirroring how ``keywords.yaml`` is edited.
"""

from __future__ import annotations

import os


def harvest_path(name: str | None = None) -> str:
    """Path to ``name``'s ``harvest.yaml`` (the active profile's when unnamed)."""
    from .. import profiles
    return os.path.join(profiles.profile_dir(name), "harvest.yaml")


def _taxonomy_default(profile: str | None) -> dict:
    """The built-in harvest spec for ``profile`` (active when unnamed); ``{}`` if none."""
    from .. import profiles
    tax = profiles.taxonomy(profile)
    spec = getattr(tax, "harvest_spec", None)
    return dict(spec) if spec else {}


def load(profile: str | None = None) -> dict:
    """Load ``harvest.yaml`` for ``profile``; fall back to the taxonomy default.

    Returns ``{}`` (and the driver no-ops) when neither a file nor a built-in
    default exists — that is the case for ``cybersec``, which is intentionally
    search-discovery-first.
    """
    p = harvest_path(profile)
    if os.path.exists(p):
        import yaml
        with open(p, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return data if isinstance(data, dict) else {}
    return _taxonomy_default(profile)


def save(spec: dict, profile: str | None = None) -> str:
    """Write ``spec`` to ``harvest.yaml`` (creating the profile dir); return the path."""
    p = harvest_path(profile)
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    import yaml
    with open(p, "w", encoding="utf-8") as f:
        yaml.safe_dump(spec, f, sort_keys=True, allow_unicode=True,
                       default_flow_style=False)
    return p
