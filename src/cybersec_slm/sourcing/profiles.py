#!/usr/bin/env python3
"""Pipeline profiles: switchable corpora, each with its own taxonomy and catalog.

A **profile** is one corpus the pipeline can build. Each owns a directory under
the data root::

    sources/profiles/<name>/keywords.yaml   # taxonomy: sub-domains + keywords
    sources/profiles/<name>/Sources.csv     # the discovered-source catalog
    sources/profiles/<name>/Blacklist.csv   # rows rejected for a red license

Switching profiles re-points every stage — sourcing discovers against the new
taxonomy, ingestion reads the new catalog, and the schema stage validates against
the new sub-domain enum — because all three resolve their paths through here.

Two profiles ship built in (see :mod:`cybersec_slm.sourcing.taxonomies`):

    ``cybersec`` -- the original 12-domain cybersecurity corpus.
    ``ubi``      -- the 4-domain Indian banking regulatory-compliance corpus.

The active profile resolves in precedence order:

    1. an explicit argument (``profile=`` on the functions that take one),
    2. ``$CYBERSEC_SLM_PROFILE`` — for a one-off run or a test, without
       disturbing what is saved on disk,
    3. ``sources/active_profile`` — the persisted choice (``profile use <name>``),
    4. :data:`taxonomies.DEFAULT_PROFILE`.

Per-profile *settings* (worker counts, caps, sourcing knobs) are namespaced by
profile in ``pipeline_settings.json`` — see
:mod:`cybersec_slm.dashboard.settings_store`.

Streamlit-free and side-effect-light (it only reads/writes small files under
``sources/``), so it is unit-testable directly.
"""

from __future__ import annotations

import os
import re

from .. import core
from . import taxonomies

# Name of the file at ``sources/`` holding the persisted active-profile name.
ACTIVE_FILE = "active_profile"
ENV_VAR = "CYBERSEC_SLM_PROFILE"

# A profile name is a directory name; keep it to something filesystem-safe rather
# than sanitising a hostile value into a path traversal.
_VALID_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class UnknownProfile(KeyError):
    """Raised when a profile name is not built in and has no directory on disk."""


def _sources_root() -> str:
    return os.path.join(core.data_root(), "sources")


def _profiles_root() -> str:
    return os.path.join(_sources_root(), "profiles")


def validate_name(name: str) -> str:
    """Return ``name`` if it is a usable profile name, else raise ``ValueError``."""
    name = (name or "").strip()
    if not _VALID_NAME.match(name):
        raise ValueError(
            f"invalid profile name {name!r}: use letters, digits, '.', '_', '-' "
            "and start with a letter or digit")
    return name


def names() -> list[str]:
    """Every known profile: the built-ins plus any created on disk, sorted."""
    known = set(taxonomies.names())
    root = _profiles_root()
    if os.path.isdir(root):
        known |= {d for d in os.listdir(root)
                  if os.path.isdir(os.path.join(root, d)) and _VALID_NAME.match(d)}
    return sorted(known)


def exists(name: str) -> bool:
    """Whether ``name`` is a built-in profile or has a directory on disk."""
    return name in taxonomies.TAXONOMIES or os.path.isdir(profile_dir(name))


def _active_file() -> str:
    return os.path.join(_sources_root(), ACTIVE_FILE)


def active() -> str:
    """The active profile name (env > persisted file > built-in default).

    Delegates to :func:`core.active_profile`. The resolution used to live here and
    be re-implemented in core once core needed a profile to build its paths, and
    two answers to "which profile am I" that can disagree is a bug waiting to
    happen: the catalog would come from one profile while the corpus was written
    under another's directory. One implementation, and this is the name everything
    outside core keeps calling.

    Never raises: an env var or file naming a profile that does not exist falls
    back to the default, so a stale pointer degrades to a working pipeline rather
    than breaking every stage's import.
    """
    return core.active_profile()


def use(name: str) -> str:
    """Persist ``name`` as the active profile; return it.

    Seeds the profile's directory (taxonomy + empty catalogs) if it does not
    exist yet, so switching to a built-in profile for the first time is a single
    step. Raises :class:`UnknownProfile` for a name that is neither built in nor
    already on disk — creating a brand-new profile is :func:`create`, so that a
    typo in ``profile use`` fails loudly instead of silently making an empty one.
    """
    name = validate_name(name)
    if not exists(name):
        raise UnknownProfile(
            f"unknown profile {name!r}; known: {names()}. "
            f"Use create() to start a new one.")
    ensure(name)
    path = _active_file()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(name + "\n")
    os.replace(tmp, path)
    return name


def profile_dir(name: str | None = None) -> str:
    """The directory holding ``name``'s taxonomy and catalogs (no I/O)."""
    return os.path.join(_profiles_root(), name or active())


def catalog_path(name: str | None = None) -> str:
    """Path to ``name``'s ``Sources.csv`` (the discovered-source catalog)."""
    return os.path.join(profile_dir(name), "Sources.csv")


def blacklist_path(name: str | None = None) -> str:
    """Path to ``name``'s ``Blacklist.csv``."""
    return os.path.join(profile_dir(name), "Blacklist.csv")


def keywords_path(name: str | None = None) -> str:
    """Path to ``name``'s editable ``keywords.yaml`` taxonomy."""
    return os.path.join(profile_dir(name), "keywords.yaml")


def sourcing_config_path(name: str | None = None) -> str:
    """Path to ``name``'s editable ``sourcing.yaml`` (the sourcing-engine settings).

    Absent by default: the engine falls back to taxonomy-derived defaults
    (:func:`cybersec_slm.sourcing.config.default_config`), so a profile sources
    without it and this file is a place to override backends/targets/quality.
    """
    return os.path.join(profile_dir(name), "sourcing.yaml")


def taxonomy(name: str | None = None) -> taxonomies.Taxonomy:
    """The built-in :class:`~.taxonomies.Taxonomy` backing profile ``name``.

    This is the *code-side default*, not what is on disk: a profile's live
    sub-domains come from its ``keywords.yaml`` via
    :mod:`cybersec_slm.sourcing.catalog`.

    A custom profile (one created with :func:`create`, with no module in
    :mod:`~.taxonomies`) gets an **empty** taxonomy carrying only the default's
    discovery knobs — engines, query qualifiers, host scope. Its sub-domains,
    codes, and vocab are deliberately empty rather than inherited: falling back to
    the default profile's would silently file a brand-new corpus under the
    *previous* corpus's sub-domains and enum codes.
    """
    name = name or active()
    if name in taxonomies.TAXONOMIES:
        return taxonomies.get(name)

    base = taxonomies.get(taxonomies.DEFAULT_PROFILE)
    return taxonomies.Taxonomy(
        domain_name=name.upper(),
        keywords={}, vocab={}, codes={},
        site_scope_hosts=base.site_scope_hosts,
        engines=base.engines,
        query_qualifier=base.query_qualifier,
        restricted_hosts={},
    )


def _write_seed_csv(path: str, rows: tuple[dict, ...] = ()) -> None:
    """Create ``path`` with the catalog header + any seed rows, if it is absent.

    Never touches an existing catalog: seeding is a first-run convenience, not
    something that should reappear after a user deletes a row it wrote.
    """
    if os.path.exists(path):
        return
    # Imported here: sourcing.sheet -> ingestion.sources -> sourcing.catalog is a
    # cycle at module scope.
    import csv as _csv

    from ..ingestion.sources import CATALOG_COLUMNS
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = _csv.DictWriter(f, fieldnames=list(CATALOG_COLUMNS),
                            extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow({c: row.get(c, "") for c in CATALOG_COLUMNS})


def ensure(name: str | None = None) -> str:
    """Create ``name``'s directory and seed any missing file; return the directory.

    Idempotent, and never overwrites: an existing ``keywords.yaml`` or catalog is
    left exactly as it is, so calling this on every run is safe and a user's edits
    survive. A built-in profile is seeded from its :class:`~.taxonomies.Taxonomy`;
    an on-disk-only one gets empty catalogs and no taxonomy (its ``keywords.yaml``
    is the caller's to write).
    """
    name = validate_name(name or active())
    d = profile_dir(name)
    os.makedirs(d, exist_ok=True)

    kw_path = keywords_path(name)
    if not os.path.exists(kw_path) and name in taxonomies.TAXONOMIES:
        tax = taxonomies.get(name)
        # Imported here to avoid a catalog <-> profiles import cycle.
        from . import catalog as _catalog
        cat = {sub: {"keywords": list(tax.keywords.get(sub, [])),
                     "code": tax.codes.get(sub, ""),
                     "vocab": sorted(tax.vocab.get(sub, set()))}
               for sub in tax.subdomains}
        _catalog.save(cat, kw_path, domain_name=tax.domain_name)

    seed = taxonomies.get(name).seed_rows if name in taxonomies.TAXONOMIES else ()
    _write_seed_csv(catalog_path(name), seed)
    return d


def create(name: str, *, domain_name: str = "", use_it: bool = False) -> str:
    """Start a new, empty profile on disk; return its directory.

    The new profile has no sub-domains — add them via
    :func:`cybersec_slm.sourcing.catalog.add_subdomain` (or the dashboard's
    Sourcing page). Raises ``FileExistsError`` if it already exists.
    """
    name = validate_name(name)
    if exists(name):
        raise FileExistsError(f"profile {name!r} already exists")
    os.makedirs(profile_dir(name), exist_ok=True)
    from . import catalog as _catalog
    _catalog.save({}, keywords_path(name),
                  domain_name=domain_name or name.upper())
    _write_seed_csv(catalog_path(name))
    if use_it:
        use(name)
    return profile_dir(name)


def info(name: str | None = None) -> dict:
    """A summary of ``name`` for the CLI/dashboard: paths, counts, active flag."""
    name = name or active()
    from . import catalog as _catalog
    kw_path = keywords_path(name)
    # profile=name throughout: this may be describing a profile that is *not* the
    # active one, and the catalog's fallbacks would otherwise be filled from
    # whichever profile happens to be live.
    cat = ({} if not (os.path.exists(kw_path) or name in taxonomies.TAXONOMIES)
           else _catalog.load(kw_path, profile=name))
    csv_path = catalog_path(name)
    rows = 0
    if os.path.exists(csv_path):
        with open(csv_path, encoding="utf-8") as f:
            rows = max(sum(1 for _ in f) - 1, 0)
    return {
        "name": name,
        "active": name == active(),
        "builtin": name in taxonomies.TAXONOMIES,
        "dir": profile_dir(name),
        "domain_name": _catalog.domain_name(kw_path, profile=name),
        "subdomains": _catalog.subdomains(cat),
        "catalog_rows": rows,
    }
