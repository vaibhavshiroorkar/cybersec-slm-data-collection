#!/usr/bin/env python3
"""CKAN ``package_search`` backend — bulk-harvest a CKAN catalog into rows.

The motivating instance is `data.gov.in <https://www.data.gov.in>`_: a CKAN portal
whose entire catalog is reachable through the standard ``package_search`` action,
and whose contents all carry GODL-India (already an allow pattern at the license
gate). So one paginated read can grow the catalog by thousands of license-clean,
India-by-construction rows without the per-source enrichment fetch that search-
based discovery pays.

How a CKAN package becomes a catalog row (matching the shape the existing 1648
hand-imported ``data.gov.in`` rows already have):

    Name            <- package ``title`` (truncated to 80, like ``row._derive_name``)
    Sub-Domain      <- :func:`~cybersec_slm.sourcing.classify.refine_domain` on
                       title + notes, against the active profile's vocab
    Description     <- package ``notes`` (truncated to 300)
    Dataset Link    <- ``<base_url>/resource/<resource slug>`` (the human landing
                       page, exactly as the existing rows link it)
    Category        <- "Dataset"
    Original Format <- "HTML" (the landing page; ingestion's website kind crawls it)
    License         <- the spec's ``license`` stamp (GODL), not scraped — the gate
                       trusts it because the host is on the profile's scope and the
                       stamp comes from this code, not from page text
    Country         <- the spec's ``country`` (India)
    Field           <- the spec's ``field`` (Finance)
    Date Added      <- today

The backend yields rows and applies the spec's quality pre-filter; it does **no**
catalog I/O (no dedup, no append) — that is the driver's job, so this stays pure
and unit-testable against a mocked CKAN payload.

API key. CKAN's ``package_search`` is public on most instances but gated on
data.gov.in; the key is read from the env var named in the spec
(``api_key_env``, default ``DATAGOVINDIA_API_KEY`` — already in ``.env.example``).
An unset key does not crash the backend; it is sent only if present, and a 403 from
the portal raises an actionable :class:`HarvestError` pointing at the env var.
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Iterator

from ...core import logger
from ..classify import refine_domain
from ..row import SHEET_COLUMNS


class HarvestError(RuntimeError):
    """Raised when a CKAN harvest cannot proceed (bad config, auth, or transport)."""


# CKAN ``package_search`` defaults. ``rows`` per page is sized for throughput
# without tripping portals that cap page size at 100; ``start`` is the offset.
_DEFAULT_ROWS = 100
_MAX_ROWS = 1000                  # CKAN's own hard ceiling on ``rows``
_MAX_PAGES = 200                  # backstop so a miscounted ``count`` cannot loop
_RETRY_ATTEMPTS = 3
_RETRY_BACKOFF = 1.0              # seconds, doubled per attempt

# A resource slug is CKAN's ``id`` (a UUID) or its ``name`` (a kebab slug). The
# existing rows link the kebab ``name`` form (``/resource/<slug>``); prefer that
# when present, else fall back to the UUID ``id`` so a nameless resource still
# resolves. ``url`` is the direct data file — kept in the row's ``Note`` so the
# ingestion ``kind`` dispatch can reach the actual data rather than the landing
# page if a future tweak prefers that.
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def _text_of(package: dict, *keys: str) -> str:
    """First non-empty string among ``package[keys]`` (CKAN fields vary by portal)."""
    for k in keys:
        v = package.get(k)
        s = str(v or "").strip()
        if s and s.lower() != "none":
            return s
    return ""


def _pick_resource(package: dict) -> dict:
    """The resource to link. Prefers a data-file resource; else the first one.

    A CKAN package carries a ``resources`` list (the individual downloadable
    files/views under one dataset). The catalog row links *one* resource landing
    page — pick the first resource that looks like real data (CSV/JSON/XLS/PDF),
    falling back to the first resource of any kind, so a package with only a
    PDF or only an API view still yields a row.
    """
    resources = package.get("resources") or []
    if not resources:
        return {}
    _DATA = {"csv", "json", "jsonl", "xlsx", "xls", "pdf", "parquet", "txt", "xml"}
    for r in resources:
        fmt = str(r.get("format") or "").strip().lower()
        if fmt in _DATA:
            return r
    return resources[0]


def _resource_slug(resource: dict) -> str:
    """The URL path segment for ``/resource/<slug>``: the kebab ``name`` or UUID."""
    name = str(resource.get("name") or "").strip()
    if name and _NAME_RE.match(name):
        return name
    rid = str(resource.get("id") or "").strip()
    if rid:
        return rid
    return ""


def _api_key(spec: dict) -> str:
    env_var = (spec.get("api_key_env") or "DATAGOVINDIA_API_KEY").strip()
    return (os.environ.get(env_var) or "").strip()


def _search_url(base_url: str, action: str) -> str:
    """The CKAN action endpoint. ``action`` is the CKAN action name or a path.

    A bare action name (``package_search``) maps to the standard
    ``/api/3/action/<name>``; a leading-slash path (``/backend/CatalogSearchApiV3``)
    is taken verbatim, so a portal whose action path is non-standard can be pointed
    at without code changes.
    """
    base = base_url.rstrip("/")
    if action.startswith("/"):
        return base + action
    return f"{base}/api/3/action/{action}"


def _build_fq(spec: dict) -> str:
    """A CKAN ``fq`` filter-query string from the spec's ``fq_groups``.

    ``fq_groups`` is a list of ``{field, values}``; each becomes
    ``field:(v1 OR v2)`` and the groups are AND-joined, matching CKAN's fq
    syntax. Returns ``""`` when no groups are configured (no facet filter).
    """
    parts = []
    for group in spec.get("fq_groups") or []:
        field = str(group.get("field") or "").strip()
        values = [str(v).strip() for v in (group.get("values") or []) if str(v).strip()]
        if not field or not values:
            continue
        joined = " OR ".join(values)
        parts.append(f"{field}:({joined})")
    return " AND ".join(parts)


def _passes_quality(text: str, spec: dict, keywords: list[str]) -> tuple[bool, str]:
    """``(keep, reason)`` for one package's title+notes under the spec's quality knobs.

    Conservative by default: the ingestion + clean stages already drop no-text and
    off-topic records, so this only rejects what is obviously junk at the catalog
    row level — an empty/too-short title, or (when ``require_any_keyword`` is set)
    a package whose title+notes hit none of the per-domain query terms. The latter
    is what keeps a finance corpus from absorbing data.gov.in's COVID and UPSC
    resources, which crept into the hand-imported 1648.
    """
    q = spec.get("quality") or {}
    min_chars = int(q.get("require_title_min_chars") or 0)
    if min_chars and len(text.split("\n")[0].strip()) < min_chars:
        return False, "title too short"
    if q.get("require_any_keyword"):
        low = text.lower()
        if not any(k.lower() in low for k in keywords if k):
            return False, "no domain keyword hit"
    return True, ""


def _map_package(package: dict, spec: dict, domain: str, today: str,
                 domain_vocab: dict[str, set[str]] | None,
                 keywords: list[str]) -> dict | None:
    """One CKAN package -> one catalog row dict, or ``None`` if it is filtered out.

    Returns ``None`` (rather than raising) when the package fails the quality
    pre-filter or has no linkable resource, so a single bad package never aborts
    a harvest. The caller tallies the drop.
    """
    title = _text_of(package, "title")
    notes = _text_of(package, "notes", "description")
    if not title:
        return None
    keep, _ = _passes_quality(f"{title}\n{notes}", spec, keywords)
    if not keep:
        return None

    resource = _pick_resource(package)
    slug = _resource_slug(resource)
    if not slug:
        return None

    base_url = (spec.get("base_url") or "").rstrip("/")
    link = f"{base_url}/resource/{slug}"
    refined = refine_domain(domain, title, notes, domain_vocab)

    row = {c: "" for c in SHEET_COLUMNS}
    row["Name"] = title[:80]
    row["Sub-Domain"] = refined
    row["Field"] = (spec.get("field") or "").strip()
    row["Country"] = (spec.get("country") or "").strip()
    row["Description"] = (notes or title)[:300]
    row["Dataset Link"] = link
    row["Category"] = "Dataset"
    row["Original Format"] = "HTML"
    row["License"] = (spec.get("license") or "").strip()
    row["Date Added"] = today
    direct = str(resource.get("url") or "").strip()
    if direct and direct != link:
        row["Note"] = f"CKAN resource data URL: {direct}"
    return row


def _fetch_page(url: str, params: dict, headers: dict, *, client=None, owns: bool):
    """One GET with retry; returns the parsed JSON dict or raises ``HarvestError``."""
    import httpx

    last_err: Exception | None = None
    for attempt in range(_RETRY_ATTEMPTS):
        try:
            if client is not None and not owns:
                resp = client.get(url, params=params, headers=headers, timeout=60)
            else:
                with httpx.Client(timeout=60, follow_redirects=True) as c:
                    resp = c.get(url, params=params, headers=headers)
            if resp.status_code == 403:
                raise HarvestError(
                    f"CKAN API returned HTTP 403 for {url}. The portal requires an "
                    f"API key; set the env var named in the spec "
                    f"(default DATAGOVINDIA_API_KEY).")
            if resp.status_code != 200:
                raise HarvestError(
                    f"CKAN API HTTP {resp.status_code} from {url}: {resp.text[:200]}")
            try:
                return resp.json()
            except ValueError as e:
                raise HarvestError(f"CKAN API did not return JSON: {e}") from e
        except httpx.HTTPError as e:
            last_err = e
            if attempt < _RETRY_ATTEMPTS - 1:
                time.sleep(_RETRY_BACKOFF * (2 ** attempt))
    raise HarvestError(f"CKAN API request to {url} failed: {last_err}") from last_err


def _iter_results(payload: dict) -> list[dict]:
    """The ``result.results`` list from a ``package_search`` response, tolerant."""
    result = payload.get("result") or {}
    if isinstance(result, dict):
        return list(result.get("results") or [])
    return []


def harvest(spec: dict, *, client=None) -> Iterator[dict]:
    """Yield catalog rows for one CKAN backend entry in ``spec``.

    ``spec`` is one element of the spec's ``backends`` list. Paginates
    ``package_search`` over each per-domain query in ``per_domain_queries``
    (round-robin across domains is the driver's concern — here we drain one query
    fully before the next, which is simplest and lets the caller interleave).

    Yields rows already quality-filtered and mapped; the driver dedups + appends.
    On a fatal error (auth, transport) raises :class:`HarvestError` after logging,
    so the driver can report which backend failed without losing the others.
    """
    from datetime import date

    base_url = (spec.get("base_url") or "").strip()
    if not base_url:
        raise HarvestError("CKAN spec is missing 'base_url'")
    action = (spec.get("action") or "package_search").strip()
    endpoint = _search_url(base_url, action)
    rows_per_page = min(int(spec.get("rows_per_page") or _DEFAULT_ROWS), _MAX_ROWS)
    max_results = int(spec.get("max_results") or 0) or None
    api_key = _api_key(spec)
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = api_key

    per_domain_queries = spec.get("per_domain_queries") or {}
    if not per_domain_queries:
        # No per-domain queries: one bare pass (all packages). Domain stays blank
        # for refine_domain to fill from title/notes; use the spec's default domain
        # if any, else "" (the driver can re-route).
        per_domain_queries = {"": [""]}

    domain_vocab = None
    try:
        from ..classify import build_domain_vocab
        domain_vocab = build_domain_vocab()
    except Exception:
        domain_vocab = None

    today = date.today().strftime("%d/%m/%Y")
    fq = _build_fq(spec)
    emitted = 0
    owns_client = client is None

    for domain, queries in per_domain_queries.items():
        for query in queries or [""]:
            start = 0
            pages = 0
            while pages < _MAX_PAGES:
                params = {"rows": rows_per_page, "start": start}
                if query:
                    params["q"] = query
                if fq:
                    params["fq"] = fq
                logger.info(f"harvest: {endpoint} q={query!r} start={start}")
                payload = _fetch_page(endpoint, params, headers,
                                      client=client, owns=owns_client)
                packages = _iter_results(payload)
                if not packages:
                    break
                kw_list = [str(q) for q in (queries or []) if str(q).strip()]
                for pkg in packages:
                    row = _map_package(pkg, spec, domain, today,
                                       domain_vocab, kw_list)
                    if row is not None:
                        yield row
                        emitted += 1
                        if max_results and emitted >= max_results:
                            return
                total = 0
                try:
                    total = int(((payload.get("result") or {})
                                 .get("count")) or 0)
                except (TypeError, ValueError):
                    total = 0
                start += len(packages)
                pages += 1
                if total and start >= total:
                    break
                if len(packages) < rows_per_page:
                    break
            if max_results and emitted >= max_results:
                return


# Expose a module object that satisfies the :class:`HarvestBackend` protocol
# (``harvest(spec, *, client=None)``). Registered by name in :mod:`.base`.
class _CKANBackend:
    """Thin callable wrapper so the registry holds a stable object, not a function."""

    def harvest(self, spec: dict, *, client=None) -> Iterator[dict]:
        return harvest(spec, client=client)


# The stable instance the registry holds. ``base.get('ckan')`` loads this module
# and registers ``backend``, so there is exactly one CKAN backend object per run.
backend = _CKANBackend()
