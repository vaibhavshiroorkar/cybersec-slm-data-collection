#!/usr/bin/env python3
"""Built-in taxonomy specs, one per pipeline profile.

A :class:`Taxonomy` is the *code-side default* for a profile: its sub-domains and
their search keywords, the schema enum codes those sub-domains map to, the hosts
discovery is biased toward or barred from, and the search engines to use. It is
the seed for a profile's editable ``keywords.yaml`` and the fallback when that
file is absent, so a fresh checkout works with no setup.

Two profiles ship with the pipeline:

    ``cybersec`` -- the original 12-domain cybersecurity corpus.
    ``ubi``      -- the 4-domain Indian banking regulatory-compliance corpus.

Which one is live is a *profile* question, not a taxonomy one — see
:mod:`cybersec_slm.sourcing.profiles`. This package only holds the data.

Adding a profile: write a module here exposing a module-level ``TAXONOMY``, then
register it in :data:`TAXONOMIES` below.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# The License cell stamped on a row from a profile's ``owned_hosts``. Recognised
# by ``ingestion.license_gate`` as commercial-ok: it means "first-party content,
# owner-authorized", which is a stronger claim than any third-party licence.
OWNED_LICENSE = "First-party (owner-authorized)"


@dataclass(frozen=True)
class Taxonomy:
    """One profile's built-in sub-domains, keywords, and discovery scope."""

    # The schema's top-level ``domain_name`` enum value (e.g. "CYBERSEC").
    domain_name: str

    # {Sub-Domain: [keyword, ...]}
    keywords: dict[str, list[str]]

    # {Sub-Domain: {distinctive term, ...}} — tie-break vocab for classification.
    vocab: dict[str, set[str]]

    # {Sub-Domain: "ENUM_CODE"} — the schema's ``subdomain_name`` values. This is
    # the name<->index contract any downstream LabelModel keys on, so codes must
    # stay stable once records exist.
    codes: dict[str, str]

    # Hosts a query is soft-scoped to via a ``site:`` clause.
    site_scope_hosts: tuple[str, ...]

    # SearXNG engines.
    engines: tuple[str, ...]

    # Query qualifiers appended to bias results toward the right kind of page.
    query_qualifier: str

    # Engines that actually honour the ``site:`` operator, used for keywords that
    # carry one. The API-based engines above (github, arxiv, ...) silently *ignore*
    # ``site:`` and answer the bare terms instead — so a ``site:`` dork run on them
    # returns confident, on-topic-looking results from entirely the wrong host,
    # which is worse than returning nothing. Empty when a profile has no ``site:``
    # keywords.
    site_engines: tuple[str, ...] = ()

    # Hosts whose content *we own* (or hold the owner's authorization for). These
    # need no third-party licence, but the licence gate is default-deny and would
    # turn them away as "unknown" — so enrichment stamps them with
    # :data:`OWNED_LICENSE` instead of trying to scrape a licence off the page.
    # This is an authorization, recorded in docs/sources/legal_scope.md, not a
    # claim that the site publishes an open licence.
    owned_hosts: tuple[str, ...] = ()

    # Catalog rows that ship with the profile, written into its Sources.csv when
    # the profile is first seeded. For sources we already know about, a seed row is
    # strictly better than a search keyword: it is deterministic, needs no search
    # engine, and cannot be rate-limited away. Each is a dict keyed by
    # ``ingestion.sources.CATALOG_COLUMNS``.
    seed_rows: tuple[dict, ...] = ()

    # {host: why} — on-topic hosts whose terms bar commercial reuse. Discovery
    # drops these before spending an enrichment fetch. Empty for profiles with no
    # such constraint.
    restricted_hosts: dict[str, str] = field(default_factory=dict)

    # The bulk-harvest spec this profile is seeded with (see
    # :mod:`cybersec_slm.sourcing.harvest.spec`). A plain dict that lands in the
    # profile's ``harvest.yaml`` on first seed, editable like ``keywords.yaml``.
    # ``None`` (the default) means this profile is search-discovery-first and has
    # no bulk backend wired — the harvest driver no-ops for it.
    harvest_spec: dict | None = None

    @property
    def subdomains(self) -> tuple[str, ...]:
        """Sub-domain names, in this taxonomy's declared order."""
        return tuple(self.keywords)


def _load() -> dict[str, Taxonomy]:
    from . import cybersec, ubi
    return {"cybersec": cybersec.TAXONOMY, "ubi": ubi.TAXONOMY}


TAXONOMIES: dict[str, Taxonomy] = _load()

# The profile used when nothing else selects one.
DEFAULT_PROFILE = "ubi"


def get(name: str) -> Taxonomy:
    """The built-in taxonomy for profile ``name``; ``KeyError`` if unknown."""
    try:
        return TAXONOMIES[name]
    except KeyError:
        raise KeyError(
            f"unknown profile {name!r}; known: {sorted(TAXONOMIES)}") from None


def names() -> tuple[str, ...]:
    """Names of every built-in profile."""
    return tuple(sorted(TAXONOMIES))
