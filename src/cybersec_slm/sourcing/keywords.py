#!/usr/bin/env python3
"""The **active profile's** taxonomy defaults, as plain module attributes.

The pipeline builds one of several switchable corpora ("profiles" — see
:mod:`cybersec_slm.sourcing.profiles`), each with its own sub-domains, search
keywords, and discovery scope. The data for each lives in
:mod:`cybersec_slm.sourcing.taxonomies`; this module is the *view* of whichever
one is active, so callers can keep reading ``keywords.DOMAIN_KEYWORDS`` without
knowing profiles exist.

These are **code-side defaults** — the seed for a profile's editable
``keywords.yaml`` and the fallback when that file is absent. The live taxonomy a
run actually uses comes from :mod:`cybersec_slm.sourcing.catalog`, which reads
the YAML. Read the catalog, not this module, when you want what is on disk.

Attributes are resolved per access (via a module ``__getattr__``) rather than
bound at import, so switching profiles mid-process is picked up. Prefer
``from . import keywords as kw`` + ``kw.DOMAIN_KEYWORDS`` over
``from .keywords import DOMAIN_KEYWORDS``: the latter binds one profile's value at
import time and will not follow a later switch.

Exposed (all derived from the active profile's ``Taxonomy``):

    DOMAIN_KEYWORDS       {Sub-Domain: [keyword, ...]}
    DOMAIN_VOCAB          {Sub-Domain: {term, ...}}      -- classification tie-break
    DOMAIN_CODES          {Sub-Domain: "ENUM_CODE"}      -- schema subdomain_name
    DOMAINS               (Sub-Domain, ...)              -- declared order
    DEFAULT_DOMAIN_NAME   str                            -- schema domain_name
    SITE_SCOPE_HOSTS      (host, ...)                    -- site: scope bias
    RESTRICTED_HOSTS      {host: why}                    -- licensing bar
    ENGINES               (engine, ...)                  -- SearXNG engines
    QUERY_QUALIFIER       str                            -- query qualifier
"""

from __future__ import annotations

from .taxonomies import Taxonomy



def taxonomy(profile: str | None = None) -> Taxonomy:
    """The active (or named) profile's built-in taxonomy."""
    from . import profiles
    return profiles.taxonomy(profile)


# Attribute name -> how to derive it from a Taxonomy. Copies are returned for the
# mutable containers so a caller mutating what it got cannot corrupt the frozen
# built-in every other caller shares.
_VIEW = {
    "DOMAIN_KEYWORDS": lambda t: {k: list(v) for k, v in t.keywords.items()},
    "DOMAIN_VOCAB": lambda t: {k: set(v) for k, v in t.vocab.items()},
    "DOMAIN_CODES": lambda t: dict(t.codes),
    "DOMAINS": lambda t: t.subdomains,
    "DEFAULT_DOMAIN_NAME": lambda t: t.domain_name,
    "SITE_SCOPE_HOSTS": lambda t: t.site_scope_hosts,
    "RESTRICTED_HOSTS": lambda t: dict(t.restricted_hosts),
    "ENGINES": lambda t: t.engines,
    "SITE_ENGINES": lambda t: t.site_engines,
    "OWNED_HOSTS": lambda t: t.owned_hosts,
    "QUERY_QUALIFIER": lambda t: t.query_qualifier,
}


def __getattr__(name: str):
    """Resolve a taxonomy attribute against the active profile (PEP 562)."""
    try:
        derive = _VIEW[name]
    except KeyError:
        raise AttributeError(
            f"module {__name__!r} has no attribute {name!r}") from None
    return derive(taxonomy())


def __dir__() -> list[str]:
    return sorted([*globals(), *_VIEW])


def site_clause(hosts: tuple[str, ...] | None = None) -> str:
    """A ``(site:a OR site:b ...)`` clause biasing a query toward licensable hosts.

    The scope is a soft bias: a scoped query that returns nothing is retried
    unscoped by the discovery driver, so recall is never lost. It is also skipped
    entirely for engines that ignore ``site:`` operators (most of the API-based
    ones this pipeline targets) — see :func:`default_engines`.
    """
    hosts = hosts if hosts is not None else taxonomy().site_scope_hosts
    return "(" + " OR ".join(f"site:{h}" for h in hosts) + ")"


def restricted_reason(host: str, profile: str | None = None) -> str:
    """Why ``host`` is barred from the corpus, or ``""`` when it is not.

    Matches ``host`` and any subdomain of it against the active profile's
    ``restricted_hosts``. These are hosts whose content is on-topic but whose
    published terms forbid the commercial reuse this corpus needs; discovery drops
    them so they never reach the (much more expensive) enrichment fetch.
    """
    h = (host or "").strip().lower().removeprefix("www.")
    for domain, reason in taxonomy(profile).restricted_hosts.items():
        if h == domain or h.endswith("." + domain):
            return reason
    return ""


def is_owned(host: str, profile: str | None = None) -> bool:
    """Whether ``host`` (or a subdomain of it) is content this profile owns.

    Owned content needs no third-party licence, but the gate is default-deny and
    would turn it away as "unknown" — so enrichment stamps it with
    :data:`~.taxonomies.OWNED_LICENSE` rather than scraping the page for a licence
    that was never going to be there.
    """
    h = (host or "").strip().lower().removeprefix("www.")
    return any(h == d or h.endswith("." + d)
               for d in taxonomy(profile).owned_hosts)


def default_engines() -> str:
    """Comma-separated default SearXNG engine list.

    These API-based engines are targeted instead of the general web engines, which
    are perpetually rate-limited (brave/google "too many requests", duckduckgo
    "access denied", startpage "CAPTCHA"). They index licensable sources directly
    and are not throttled. Because they ignore ``site:`` operators, the site-scope
    clause is not applied when they are in use — and a keyword that carries its own
    ``site:`` needs :func:`engines_for_keyword` instead.
    """
    t = taxonomy()
    return ",".join(t.engines)


def engines_for_keyword(keyword: str) -> str:
    """Engines to run ``keyword`` on: the site-honouring set when it is a dork.

    The default engines (github, arxiv, openaire, semantic scholar) *ignore* the
    ``site:`` operator rather than erroring on it: given ``site:example.com basel
    iii``, they drop the operator and answer "basel iii", returning plausible
    results from entirely the wrong host. So a ``site:`` keyword is not merely
    unhelpful there — it is actively misleading. Route those to the profile's
    ``site_engines`` (a general web engine that honours the operator), and leave
    everything else on the defaults. A profile that declares no ``site_engines``
    falls back to the defaults unchanged.
    """
    t = taxonomy()
    if "site:" in (keyword or "").lower() and t.site_engines:
        return ",".join(t.site_engines)
    return default_engines()


def keyword_sets() -> list[tuple[dict[str, list[str]], str]]:
    """``[(keyword_dict, qualifier), ...]`` from the built-in defaults.

    Mirrors :func:`cybersec_slm.sourcing.catalog.keyword_sets`, which reads the
    live (persisted, user-editable) taxonomy — prefer that one for a real run.
    """
    t = taxonomy()
    return [({k: list(v) for k, v in t.keywords.items()}, t.query_qualifier)]
