#!/usr/bin/env python3
"""Pluggable bulk-harvest backends for the sourcing stage.

The search-based discovery in :mod:`cybersec_slm.sourcing.run` grows a catalog one
SearXNG hit at a time, with one enrichment HTTP call per candidate. That is the
right tool for finding *novel* sources across the open web, but it is the wrong one
for topping up a corpus from a single large, license-clean portal whose entire
catalog is reachable through one paginated API. India's
`data.gov.in <https://www.data.gov.in>`_ is the motivating case: it is a CKAN
instance whose contents all carry GODL-India (already allowed by the license gate),
so a bulk harvest can stamp every row's license from the catalog response itself —
no per-source fetch, no rate-limit dance, orders of magnitude faster than search.

A backend is anything that, given a :class:`HarvestSpec`, yields catalog-row dicts
in the :data:`~cybersec_slm.ingestion.sources.CATALOG_COLUMNS` shape (the same
shape :func:`cybersec_slm.sourcing.row.build_manual_row` produces). Backends are
registered by name in :data:`BACKENDS`; the driver
(:mod:`cybersec_slm.sourcing.harvest.run`) looks one up from a profile's
``harvest.yaml`` and feeds it the spec. Adding a non-CKAN bulk source later means
writing a new backend module and registering it — the driver does not change.

The spec is deliberately plain data (a dict loaded from YAML) rather than a class
hierarchy, so a profile's ``harvest.yaml`` is editable by hand exactly like its
``keywords.yaml`` — see :mod:`cybersec_slm.sourcing.harvest.spec` for the loader.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol


class HarvestBackend(Protocol):
    """A bulk catalog harvester.

    Implementations are *generators* of catalog-row dicts (keys from
    :data:`~cybersec_slm.ingestion.sources.CATALOG_COLUMNS`). They do no catalog
    I/O themselves — no dedup, no append — that is the driver's job, so a backend
    stays pure and unit-testable against a mocked API payload. Quality filtering
    at the row level (drop empty titles, require a finance keyword) belongs here;
    cross-source dedup and the per-domain deficit accounting belong in the driver.
    """

    def harvest(self, spec: dict, *, client=None) -> Iterator[dict]:
        """Yield candidate catalog rows for one backend entry in ``spec``.

        ``spec`` is one element of the spec's ``backends`` list (the per-backend
        block: ``base_url``, ``action``, queries, quality knobs, …). ``client`` is
        an optional shared ``httpx.Client`` for connection reuse across pages.
        """
        ...


# name -> backend. The CKAN backend is registered lazily on first lookup so that
# importing this module never requires httpx (it is an ingestion dependency, not a
# sourcing one) and a test can stub the registry without touching the network.
_BACKENDS: dict[str, HarvestBackend] = {}


def register(name: str, backend: HarvestBackend) -> None:
    """Add (or replace) the backend known as ``name``."""
    _BACKENDS[name] = backend


def get(name: str) -> HarvestBackend:
    """Look up backend ``name``, lazily loading the built-in CKAN backend."""
    if name not in _BACKENDS and name == "ckan":
        from . import ckan
        # ``ckan`` exposes a ``backend`` attribute: a stable object whose
        # ``harvest`` method satisfies the protocol (so the registry holds an
        # object, not the bare function, for a cleaner protocol match).
        register("ckan", ckan.backend)
    try:
        return _BACKENDS[name]
    except KeyError:
        raise KeyError(
            f"unknown harvest backend {name!r}; registered: {sorted(_BACKENDS)}") from None
