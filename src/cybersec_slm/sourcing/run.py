#!/usr/bin/env python3
"""Orchestrate keyword search -> dedup -> enrich -> append for the sourcing stage.

Pipeline per run:

    build a round-robin schedule that interleaves every selected Sub-Domain's
    keywords, so results are gathered *evenly across domains* rather than filling
    the first domain before the next.

    for each result page (deepening only when a budget asks for more):
        for each (domain, keyword) shot, in round-robin order:
            search (SearXNG) -> results          (resilient: one query failing
                                                  never aborts the whole run)
            for each result:
                drop obvious non-sources (quality filter)
                drop if its link is already in Sources.csv, or seen this run
                build a catalog row and, concurrently, enrich it (license first)
    write the survivors to a local review CSV (always) and, unless --dry-run,
    append them to the catalog ``sources/Sources.csv``.

A run is bounded by a **time budget** (``max_minutes``) and/or a **source cap**
(``max_total``); it stops at whichever is reached first. With neither set it makes
a single page-1 pass. ``max_per_domain`` optionally caps new rows per Sub-Domain.

Enrichment (``enrich``, default on) fetches each row's License and host metadata
concurrently on a thread pool - the license is the priority, so every kept source
lands in the catalog with its License column filled for the ingestion gate. Each
source is logged as it is found and again as its license resolves, so the run
streams its progress one source at a time.

The per-run review CSV under ``logs/discovered/`` is a safety net; a sidecar
``summary-*.json`` records the per-keyword hit/new counts, the license fill rate,
and a ``funnel`` block (see :mod:`cybersec_slm.sourcing.stats`) tallying every hit
the run turned away and why — so the dashboard can show not just what ran, but what
it cost.
"""

from __future__ import annotations

import csv
import json
import os
import time
import urllib.parse
from collections import deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import date

from ..core import LOGS, logger
from ..ingestion.license_gate import license_verdict
from . import catalog
from . import keywords as kw
from .classify import build_domain_vocab
from .enrich import Enricher
from .keywords import default_engines
from .quality import KEEP, reject_host
from .quality import classify as quality_classify
from .row import SHEET_COLUMNS, build_row, row_to_list
from .search import SearchError, searxng_search, Result
from .sheet import append_rows, existing_links, normalize_url, valid_counts_by_subdomain
from .stats import Funnel


def default_catalog() -> str:
    """The catalog this pipeline curates: the active profile's ``Sources.csv``."""
    from . import profiles
    return profiles.catalog_path()

# Safety backstop on how many result pages a budgeted run will walk before giving
# up, so an unreachable target can never loop forever. The exhaustion check (a full
# page that adds nothing new) normally stops the run well before this.
_MAX_SWEEP_PAGES = 20

# Abort a run only after this many *consecutive* search failures (the engine died
# mid-run). A single failing query is logged and skipped.
_FAIL_ABORT = 20


def _write_csv(rows: list[dict[str, str]], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(SHEET_COLUMNS)
        for r in rows:
            w.writerow(row_to_list(r))


def _write_summary(summary: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)


def _extract_host(url: str) -> str:
    """Hostname from a URL, ``www.``-stripped; empty string on failure."""
    try:
        host = urllib.parse.urlparse(url).hostname or ""
        return host.removeprefix("www.")
    except Exception:
        return ""


# Per-mode filetype qualifiers appended to site-dork shots so we collect
# structured data files (datasets mode) and PDF documents (both modes).
_DORK_FILETYPES: dict[str, tuple[str, ...]] = {
    "datasets": ("filetype:pdf", "filetype:csv", "filetype:xlsx", "filetype:json"),
    "text":     ("filetype:pdf",),
    "both":     ("filetype:pdf", "filetype:csv", "filetype:xlsx", "filetype:json"),
}


def _domain_shots(selected: list[str], cat: dict, mode: str,
                  countries: list[str] | None = None,
                  fields: list[str] | None = None
                  ) -> dict[str, list[tuple[str, str, bool]]]:
    """Per-domain ordered keyword shots: ``{domain: [(keyword, qualifier, is_ds)]}``.

    The discovery driver drains one *result* per domain per rotation from these,
    so sources land evenly across the selected sub-domains rather than filling the
    first domain before the next.

    Shots are ordered in three tiers within each domain:

    1. ``site:host keyword`` dorks  — auto-generated from the domain's direct
       links: for every (hostname, keyword) pair we emit a bare site-scoped query
       and one per filetype in :data:`_DORK_FILETYPES` for the run mode.
       These use the profile's ``site_engines`` (general engines that honour
       ``site:``) via :func:`~keywords.engines_for_keyword`.
    2. Plain/generic keyword searches  — the keywords from ``keywords.yaml`` as
       they are, with no ``site:`` prefix.  These run after the site-dorks for
       each domain are exhausted.

    Direct links themselves (the raw URLs from the catalog's ``links`` list) are
    pre-loaded into the cursor buffer *before* any shots fire, so the full
    priority order is:

        direct links  >  site-dork shots  >  generic keyword searches
    """
    kw_sets = catalog.keyword_sets(mode, cat)   # list; safe to iterate twice
    filetypes = _DORK_FILETYPES.get(mode, ("filetype:pdf",))

    per_domain: dict[str, list[tuple[str, str, bool]]] = {d: [] for d in selected}

    for domain in selected:
        # ---- tier 1: site-dork shots from direct-link hostnames ---------------
        d_links = cat.get(domain, {}).get("links", [])
        # Deduplicate hostnames (preserving order) so two links on the same host
        # don't produce duplicate dork sets.
        seen_hosts: dict[str, None] = {}
        for lnk in d_links:
            h = _extract_host(lnk)
            if h:
                seen_hosts[h] = None
        hostnames = list(seen_hosts)

        site_shots: list[tuple[str, str, bool]] = []
        if hostnames:
            for kwdict, qualifier in kw_sets:
                is_ds = qualifier == kw.QUERY_QUALIFIER
                for keyword in kwdict.get(domain, []):
                    for host in hostnames:
                        # broad site-scoped query
                        site_shots.append((f"site:{host} {keyword}", qualifier, is_ds))
                        # filetype-specific queries (pdf, csv, …)
                        for ft in filetypes:
                            site_shots.append(
                                (f"site:{host} {keyword} {ft}", qualifier, is_ds))

        # ---- tier 2: plain keyword searches -----------------------------------
        # Build the suffix to inject for geographical/field targeting
        suffix_parts = []
        if countries and "Global" not in countries:
            suffix_parts.extend(countries)
        if fields:
            suffix_parts.extend(fields)
        suffix = " " + " ".join(suffix_parts) if suffix_parts else ""

        generic_shots: list[tuple[str, str, bool]] = []
        for kwdict, qualifier in kw_sets:
            is_ds = qualifier == kw.QUERY_QUALIFIER
            for keyword in kwdict.get(domain, []):
                injected_keyword = f"{keyword}{suffix}"
                generic_shots.append((injected_keyword, qualifier, is_ds))

        per_domain[domain] = site_shots + generic_shots

    return per_domain


def _enrich_and_log(enricher: Enricher, row: dict) -> None:
    """Enrich one row in place and log its resolved license (the per-source line)."""
    enricher.enrich(row)
    lic = str(row.get("License") or "").strip() or "unknown"
    logger.info(f"source: license={lic} :: {row.get('Dataset Link', '')}")


def _fill_loop(selected, target_per_domain, global_cap, max_per_domain, csv_path, cursor, seen,
               per_domain_count, by_keyword_agg, new_rows, refill, expired,
               quality_filter, today, enricher, pool, dry_run, domain_vocab,
               funnel, valid_only):
    """Valid-gated per-domain fill: top each selected domain up to its
    commercial-valid target.

    Reads each domain's existing commercial-valid count to size its deficit, then
    round-robins over the still-short domains. Each turn gathers a batch of deduped,
    quality-passing candidates (via the shared ``refill`` cursor, which pages deeper
    for the paginating engines), enriches the batch concurrently on ``pool``, and
    appends only the rows the license gate passes as commercial - counting them
    toward the deficit. A domain stops at its target or when its search is
    exhausted; the run stops globally at ``global_cap`` valid rows, on the time
    budget (``expired``), or when every domain is satisfied/exhausted. Rows are
    appended per batch so a long run keeps its progress. Returns
    ``(appended, target_reached)``.
    """
    existing_valid = valid_counts_by_subdomain(csv_path)
    if target_per_domain == float('inf'):
        need = {d: float('inf') for d in selected}
    else:
        need = {d: max(0, target_per_domain - existing_valid.get(d, 0)) for d in selected}
    active = [d for d in selected if need[d] > 0 and not cursor[d]["exhausted"]]
    deficits = {d: need[d] for d in selected if need[d] > 0}
    logger.info(f"source: valid-gated loop; target/domain={target_per_domain}; "
                f"{len(active)} domain(s) active")
    appended = 0

    def _capped() -> bool:
        return global_cap is not None and len(new_rows) >= global_cap

    def _gather_batch(domain: str) -> list[tuple[str, dict]]:
        c = cursor[domain]
        if not c["buffer"] and not c["exhausted"]:
            refill(domain)
        batch: list[tuple[str, dict]] = []
        while c["buffer"]:
            keyword, res = c["buffer"].popleft()
            category, _ = quality_classify(res)
            if quality_filter and category != KEEP:
                funnel.drop(domain, category, reject_host(res))
                continue
            norm = normalize_url(res.link)
            if not norm or norm in seen:
                funnel.duplicate(domain)
                continue
            seen.add(norm)                          # dedup within this run too
            funnel.candidate(domain)
            batch.append((keyword, build_row(res, domain, today=today,
                                             domain_vocab=domain_vocab)))
        return batch

    while active and not expired() and not _capped():
        for domain in list(active):
            if expired() or _capped():
                break
            batch = _gather_batch(domain)
            if not batch:
                if cursor[domain]["exhausted"]:
                    active.remove(domain)
                continue
            if enricher is not None:
                futs = [pool.submit(_enrich_and_log, enricher, row)
                        for _, row in batch]
                for fu in futs:
                    try:
                        fu.result()
                    except Exception as e:          # noqa: BLE001 - best-effort
                        logger.debug(f"source: enrich task failed: {e}")
            # Every gathered row has now been enriched, so every one has reached the
            # license gate — tally them all here rather than inside the keep loop
            # below, which breaks early once the domain's deficit is met. Counting
            # there would silently drop the verdicts of the tail of the batch and
            # leave the funnel's candidates != sum(license) — i.e. not a funnel.
            for _, row in batch:
                funnel.verdict(license_verdict(row.get("License")))

            kept: list[dict] = []
            for keyword, row in batch:
                if need[domain] <= 0 or _capped() or (max_per_domain is not None and per_domain_count[domain] >= max_per_domain):
                    break
                if valid_only and license_verdict(row.get("License")) != "ok":
                    continue                        # gathered + enriched, but not kept
                new_rows.append(row)
                kept.append(row)
                per_domain_count[domain] += 1
                agg = by_keyword_agg.setdefault(
                    (domain, keyword),
                    {"domain": domain, "keyword": keyword, "hits": 0, "new": 0})
                agg["new"] += 1
                need[domain] -= 1
                logger.info(f"source: [{domain}] valid {len(new_rows)}"
                            f"/{global_cap or '*'} + {row['Name']} :: "
                            f"{row['Dataset Link']}")
            if kept and not dry_run:
                appended += append_rows(csv_path, kept)
            if need[domain] <= 0 or cursor[domain]["exhausted"]:
                if domain in active:
                    active.remove(domain)

    target_reached = all(need[d] <= 0 for d in selected)
    return appended, target_reached


def discover(csv_path: str | None = None, *, domains: list[str] | None = None,
             per_keyword: int = 5, max_per_domain: int | None = None,
             max_total: int | None = None, max_minutes: float | None = None,
             mode: str = "datasets", dry_run: bool = False,
             out_csv: str | None = None, base_url: str | None = None,
             language: str = "en", time_range: str | None = "year",
             site_scope: bool = True, quality_filter: bool = True,
             workers: int = 12, client=None, enrich: bool = True,
             engines: str | None = None, target_per_domain: int | None = None,
             valid_only: bool = True,
             countries: list[str] | None = None, fields: list[str] | None = None,
             clock: Callable[[], float] = time.monotonic) -> dict:
    """Run sourcing and return a summary dict.

    ``mode`` selects the keyword catalog: ``datasets`` (corpora/repos), ``text``
    (articles/docs/writeups), or ``both``. Results are gathered round-robin across
    the selected domains, so coverage stays even.

    Queries are routed to reliable SearXNG engines (``engines``; arg > env
    ``$SEARXNG_ENGINES`` > a GitHub-first default per mode) instead of the
    perpetually rate-limited general web engines. Those API engines index sources
    directly and ignore ``site:`` operators, so the site-scope clause and the
    dataset/text query qualifier are not applied when engines are in use (the norm).

    Two run shapes:

    - **Fill mode** (``target_per_domain`` set): read each selected domain's
      existing commercial-valid count, then top it up toward the target. Each turn
      gathers a batch of candidates for a still-short domain, enriches them, and
      appends only the rows the license gate passes as commercial (``valid_only``
      is implied), counting them toward the deficit; a domain stops at its target
      or when its search is exhausted. The run stops globally at ``max_total`` valid
      rows or when every domain is satisfied/exhausted.
    - **Simple mode** (no ``target_per_domain``): the historic run. Bounded by
      ``max_minutes`` and/or ``max_total`` (stops at whichever is hit first; with
      neither, a single page-1 pass). ``max_per_domain`` caps new rows per
      Sub-Domain. ``valid_only`` optionally drops non-commercial rows before append.

    ``time_range`` (``day``/``week``/``month``/``year``/``None``) biases toward fresh
    results and falls back to a bare query when it would return nothing, so recall
    is never lost. ``quality_filter`` drops obvious non-sources before enrichment.

    With ``enrich`` (default), each kept row is enriched concurrently on a
    ``workers``-thread pool - the License column first, then size/author/tags. In
    fill mode enrichment is on the critical path (the license is needed to gate),
    but stays concurrent. Enrichment is best-effort: a failed lookup leaves a field
    blank and never aborts the run.

    ``base_url`` overrides ``$SEARXNG_URL``; ``client`` is an optional shared
    ``httpx.Client``; ``clock`` is the monotonic time source (injectable for tests).

    Returns ``{"found", "new", "appended", "csv", "mode", "domains", "target",
    "target_reached", "by_domain", "by_keyword", "elapsed_s", "max_minutes",
    "license_filled", "license_rate", "target_per_domain", "engines"}``.
    """
    csv_path = csv_path or default_catalog()
    started = clock()

    if not enrich:
        valid_only = False

    cat = catalog.load()
    all_domains = catalog.subdomains(cat)
    selected = domains or all_domains
    unknown = [d for d in selected if d not in cat]
    if unknown:
        raise ValueError(f"unknown Sub-Domain(s): {unknown}. Valid: {all_domains}")
    # Computed once per run (not per result) and passed into every build_row call.
    domain_vocab = build_domain_vocab(cat)

    logger.info(f"source: reading existing links from {csv_path}")
    seen = existing_links(csv_path)
    logger.info(f"source: {len(seen)} links already in the catalog")

    # A shared client is reused by both search and enrichment (connection reuse).
    owns_client = client is None
    if client is None:
        import httpx
        client = httpx.Client(timeout=30, follow_redirects=True)
    enricher = Enricher(client=client) if enrich else None
    pool = ThreadPoolExecutor(max_workers=max(1, int(workers))) if enrich else None
    futures: list = []

    today = date.today().strftime("%d/%m/%Y")
    new_rows: list[dict[str, str]] = []
    funnel = Funnel()
    per_domain_count: dict[str, int] = {d: 0 for d in selected}
    by_keyword_agg: dict[tuple[str, str], dict] = {}

    per_domain_shots = _domain_shots(selected, cat, mode, countries, fields)
    target = max_total
    deadline = started + max_minutes * 60 if max_minutes else None
    # Route queries to reliable engines (arg > $SEARXNG_ENGINES > a per-mode
    # default) instead of the rate-limited general web engines. These API engines
    # index sources directly and ignore site:/qualifier, so both are dropped while
    # engines are in use (the norm).
    #
    # The exception is a keyword that carries its own ``site:`` (the ubi profile's
    # own-content dorks): the API engines ignore that operator and answer the bare
    # terms, returning plausible results from the wrong host entirely, so those
    # keywords are routed to a general engine that honours it. An explicit
    # --engines override still wins over both.
    engines_override = engines or os.environ.get("SEARXNG_ENGINES") or None

    def _engines_for(is_ds: bool, keyword: str = "") -> str:
        return engines_override or kw.engines_for_keyword(keyword, is_ds)

    # Valid-gated search floors the per-query slice so a single GitHub page (up to ~30) is
    # captured rather than truncated to the historic default of 5.
    effective_per_keyword = max(per_keyword, 20)

    def _reached() -> bool:
        return target is not None and len(new_rows) >= target

    def _expired() -> bool:
        return deadline is not None and clock() >= deadline

    def _domain_full(domain: str) -> bool:
        return max_per_domain is not None and per_domain_count[domain] >= max_per_domain

    # With a budget (or a fill target) set, page deeper until it is met or the
    # search space is exhausted; without one, a single page-1 pass is the historic run.
    last_page = (_MAX_SWEEP_PAGES
                 if (target is not None or deadline is not None or target_per_domain is not None) else 1)

    # Per-domain search cursor + a small buffer of pending results, so the driver
    # can hand out one result per domain per rotation (even distribution) without
    # re-searching. A whole page (all of a domain's keywords) that yields nothing
    # marks that domain exhausted.
    #
    # Priority order within each domain:
    #   1. Direct links  (pre-loaded into the buffer here — processed before any search)
    #   2. site:-scoped dorks  (targeted known-website queries, ordered first in shots)
    #   3. Generic keyword searches
    cursor = {}
    for d in selected:
        buf = deque()
        d_links = cat.get(d, {}).get("links", [])
        for link in d_links:
            funnel.hit(d)
            agg = by_keyword_agg.setdefault(
                (d, "<direct link>"),
                {"domain": d, "keyword": "<direct link>", "hits": 0, "new": 0})
            agg["hits"] += 1
            buf.append(("<direct link>", Result(title="", link=link, snippet="direct link")))
        
        has_shots = bool(per_domain_shots[d])
        cursor[d] = {"si": 0, "page": 1, "page_hits": 0, "buffer": buf,
                     "exhausted": not has_shots and not buf}
    fail_state = {"consecutive": 0, "succeeded_once": False}

    def _search(base_query: str, is_ds: bool, page: int):
        """Run one keyword query on the targeted engines, retrying without the
        freshness filter when a timed query would return nothing."""
        eng = _engines_for(is_ds, base_query)
        results = searxng_search(base_query, url=base_url, num=effective_per_keyword,
                                 language=language, client=client, pageno=page,
                                 time_range=time_range, engines=eng)
        # Freshness is a soft bias: a timed query that finds nothing is retried
        # without the time filter so recall is never lost.
        if not results and time_range:
            try:
                results = searxng_search(base_query, url=base_url,
                                         num=effective_per_keyword, language=language,
                                         client=client, pageno=page, time_range=None,
                                         engines=eng)
            except SearchError:
                results = []
        return results

    def _refill(domain: str) -> None:
        """Search this domain's next keyword(s) until its buffer has results."""
        c = cursor[domain]
        shots = per_domain_shots[domain]
        while not c["buffer"] and not c["exhausted"]:
            if not shots:
                c["exhausted"] = True
                break
            if c["page"] > last_page:
                c["exhausted"] = True
                break
            keyword, qualifier, is_ds = shots[c["si"]]
            # The targeted API engines ignore the dataset/text qualifier and score
            # a bare keyword best, so the qualifier is not appended to the query.
            base_query = keyword
            try:
                results = _search(base_query, is_ds, c["page"])
                fail_state["succeeded_once"] = True
                fail_state["consecutive"] = 0
            except SearchError as e:
                logger.warning(f"source: search failed for {keyword!r} "
                               f"p{c['page']}: {e}")
                if not fail_state["succeeded_once"]:
                    # The very first query failed outright: the instance is almost
                    # certainly unreachable or has JSON disabled. Fail fast with the
                    # actionable message rather than churning every keyword.
                    raise SearchError(
                        f"SearXNG discovery could not start - the first query "
                        f"failed. {e}") from e
                fail_state["consecutive"] += 1
                if fail_state["consecutive"] >= _FAIL_ABORT:
                    raise SearchError(
                        f"aborting after {fail_state['consecutive']} consecutive "
                        f"search failures; last: {e}") from e
                results = []
            for res in results:
                funnel.hit(domain)
                agg = by_keyword_agg.setdefault(
                    (domain, keyword),
                    {"domain": domain, "keyword": keyword, "hits": 0, "new": 0})
                agg["hits"] += 1
                c["buffer"].append((keyword, res))
            c["page_hits"] += len(results)
            c["si"] += 1
            if c["si"] >= len(shots):              # finished a full page of keywords
                if c["page_hits"] == 0:            # a whole page found nothing -> done
                    c["exhausted"] = True
                c["si"] = 0
                c["page"] += 1
                c["page_hits"] = 0
                if c["page"] > last_page:
                    c["exhausted"] = True

    appended_in_fill = 0
    fill_target_reached: bool | None = None
    try:
        appended_in_fill, fill_target_reached = _fill_loop(
            selected, target_per_domain if target_per_domain is not None else float('inf'),
            target, max_per_domain, csv_path, cursor, seen,
            per_domain_count, by_keyword_agg, new_rows, _refill, _expired,
            quality_filter, today, enricher, pool, dry_run, domain_vocab,
            funnel, valid_only)
    finally:
        if pool is not None:
            pool.shutdown(wait=False)
        if owns_client:
            client.close()

    license_filled = sum(1 for r in new_rows if str(r.get("License") or "").strip())

    by_domain = dict(per_domain_count)
    for domain in selected:
        logger.info(f"source: {domain}: {per_domain_count[domain]} new")
    by_keyword = list(by_keyword_agg.values())

    stamp = f"{date.today():%Y%m%d}"
    review_csv = out_csv or os.path.join(LOGS, "discovered", f"discovered-{stamp}.csv")
    _write_csv(new_rows, review_csv)
    logger.info(f"source: wrote {len(new_rows)} candidate rows -> {review_csv}")

    appended = appended_in_fill
    if not dry_run:
        logger.info(f"source: appended {appended} rows to {csv_path}")
    else:
        logger.info("source: dry-run, not appending to the catalog")

    elapsed_s = round(clock() - started, 1)
    logger.info(f"source: done in {elapsed_s}s - {len(new_rows)} new, "
                f"{license_filled} licensed")
    funnel.appended = appended
    summary = {"found": funnel.found, "new": len(new_rows), "appended": appended,
               "funnel": funnel.as_dict(),
               "csv": review_csv, "mode": mode, "domains": selected,
               "target": target, "target_per_domain": target_per_domain,
               "engines": engines_override or default_engines(True),
               "target_reached": fill_target_reached or _reached() or (target is None and target_per_domain is None),
               "by_domain": by_domain, "by_keyword": by_keyword,
               "elapsed_s": elapsed_s, "max_minutes": max_minutes,
               "license_filled": license_filled,
               "license_rate": round(license_filled / len(new_rows), 3) if new_rows else 0.0}
    _write_summary(summary, os.path.join(LOGS, "discovered", f"summary-{stamp}.json"))
    return summary
