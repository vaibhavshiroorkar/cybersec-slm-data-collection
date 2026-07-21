#!/usr/bin/env python3
"""The one sourcing engine: config -> backends -> gate -> enrich -> catalog.

Replaces the three overlapping engines (legacy SearXNG ``discover``, ``harvest``,
and ``hybrid``) with a single orchestrator driven by one per-profile
``sourcing.yaml`` (:mod:`cybersec_slm.sourcing.config`). One run:

    load config -> pick enabled backends in priority order
    round-robin across the selected sub-domains (even coverage), and for each,
      pull the next (backend, keyword) shot and fetch a batch of Candidates
      pass every Candidate through the single gate (:mod:`.gates`):
        host/shape drop -> off-topic drop -> dedup -> liveness -> license verdict
      build a catalog row (reusing :func:`row.build_row`), overlay the backend's
        REAL metadata (license included, never fabricated), and append it
    stop on the global cap, the per-sub-domain valid target, the time budget,
      or when every backend/keyword is exhausted
    write a review CSV + summary-*.json funnel the dashboard reads

Every candidate from every backend passes the *same* gate, so a licensing-
restricted host can never be admitted on backend reputation — the contradiction the
old two-engine setup carried is designed out.
"""

from __future__ import annotations

import csv
import json
import os
import time
from collections import deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import date

from ..core import LOGS, logger
from ..ingestion.license_gate import license_verdict
from . import catalog, config, gates
from .backends import get_backend
from .classify import build_domain_vocab
from .config import API_BACKENDS, SourcingConfig
from .dedup import Dedup
from .enrich import Enricher
from .row import SHEET_COLUMNS, build_row, row_to_list
from .sheet import append_rows, valid_counts_by_subdomain
from .stats import Funnel

# Safety backstop: never run more than this many total (subdomain, backend, keyword)
# shots in one run, so an unreachable target cannot loop forever. Exhaustion (every
# shot spent) normally ends a run well before this.
_MAX_SHOTS = 100_000


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


def _country_slots(n: int, bias: dict[str, float]) -> list[str]:
    """Assign ``n`` query slots to countries in proportion to ``bias``.

    Sainte-Laguë sequential allocation: each slot goes to whichever country has the
    highest ``weight / (2 * already_allocated + 1)``, ties broken by name. That
    yields both the right totals (``{India: 0.65, Global: 0.35}`` over 20 keywords
    gives 13 India-aimed and 7 plain) *and* an evenly spread order.

    Spreading is the point, not a nicety. A run routinely stops early on its row cap
    or time budget, so an apportionment that emitted all the India queries first —
    or last — would mean an interrupted run had asked only one kind. Deterministic
    (no RNG), so the same config always produces the same query plan.
    """
    if n <= 0:
        return []
    live = {c: float(w) for c, w in (bias or {}).items() if float(w) > 0}
    if not live:
        return [config.GLOBAL] * n

    allocated = dict.fromkeys(live, 0)
    slots: list[str] = []
    for _ in range(n):
        c = max(sorted(live), key=lambda c: live[c] / (2 * allocated[c] + 1))
        allocated[c] += 1
        slots.append(c)
    return slots


def _aim(keyword: str, country: str, cfg: SourcingConfig) -> str:
    """``keyword`` aimed at ``country`` — the qualifier appended, or left alone.

    A keyword that already names the country ("RBI master direction KYC 2016",
    "India PMLA case corpus") is returned unchanged: re-qualifying it to
    "... India India" only makes the query worse.
    """
    qualifier = cfg.qualifier_for(country)
    if not qualifier:
        return keyword
    low = keyword.lower()
    if qualifier.lower() in low:
        return keyword
    # Already-local keywords carry the country's own hint terms (rbi, sebi, npci...).
    from .row import country_for
    if country_for("", keyword, cfg.country_hints) == country:
        return keyword
    return f"{keyword} {qualifier}"


def _build_shots(cfg: SourcingConfig, selected: list[str]) -> dict[str, deque]:
    """Per-sub-domain queue of ``(backend_name, keyword)`` shots, interleaved.

    Shots are **keyword-major**: every enabled backend gets a turn on the first
    keyword before any backend sees the second. Backend priority still decides the
    order *within* a keyword, so the real-metadata APIs are asked before the
    low-signal SearXNG last-resort.

    Draining one backend's entire keyword list first (the original order) meant a
    slow or unreachable backend burned one timeout per keyword — 119 of them, ~30s
    each — before any other backend ran at all, which is indistinguishable from a
    hung run. Interleaving caps that cost at one shot per rotation, and the
    circuit breaker in :func:`source` then drops the backend entirely.

    Each keyword is also **aimed at a country** per :func:`_country_slots`, so the
    profile's ``country.bias`` (or a hard ``country.filter``) shapes the queries
    themselves. This is the half that actually produces regional data: a filter
    alone only discards what the backends already returned, and if every query is
    global then filtering for India just yields an empty run.
    """
    order = cfg.enabled_backends()
    bias = cfg.targeting_bias()
    shots: dict[str, deque] = {}
    for sd in selected:
        kws = list(cfg.keywords.get(sd, []))
        slots = _country_slots(len(kws), bias)
        q: deque = deque()
        for kw, country in zip(kws, slots, strict=True):
            query = _aim(kw, country, cfg)
            for bname in order:
                q.append((bname, query))
        shots[sd] = q
    return shots


def source(profile: str | None = None, *, cfg: SourcingConfig | None = None,
           subdomains: list[str] | None = None, max_total: int | None = None,
           target_per_subdomain: int | None = None, dry_run: bool = False,
           enrich: bool = True, backends: list[str] | None = None,
           verify_liveness: bool | None = None, out_csv: str | None = None,
           workers: int | None = None,
           clock: Callable[[], float] = time.monotonic,
           max_minutes: float | None = None) -> dict:
    """Run sourcing for a profile and return a summary dict.

    ``cfg`` overrides the on-disk config (for tests/one-offs). ``subdomains`` limits
    the run to a subset; ``backends`` limits which backends fire. ``max_total`` caps
    total new rows; ``target_per_subdomain`` tops each sub-domain up to that many
    *commercial-valid* rows (seeded from the live catalog). ``max_minutes`` is a wall
    clock budget. ``dry_run`` gathers but does not append. Returns a summary whose
    ``funnel``/``by_domain``/``by_keyword`` shape the dashboard reads.
    """
    started = clock()
    cfg = cfg or config.load(profile)
    if max_total is not None:
        cfg.target_total = max_total
    if target_per_subdomain is not None:
        cfg.target_per_subdomain = target_per_subdomain
    if verify_liveness is not None:
        cfg.verify_liveness = verify_liveness
    if workers is not None:
        cfg.workers = max(1, workers)
    if backends is not None:
        for name, bc in cfg.backends.items():
            bc.enabled = name in backends

    csv_path = cfg.output_csv
    cat = catalog.load(profile=cfg.profile)
    all_subs = catalog.subdomains(cat)
    selected = subdomains or list(cfg.keywords) or all_subs
    unknown = [s for s in selected if s not in cat]
    if unknown:
        raise ValueError(f"unknown Sub-Domain(s): {unknown}. Valid: {all_subs}")

    vocab = build_domain_vocab(cat)
    dedup = Dedup(csv_path)
    logger.info(f"source: {len(dedup)} links already in {csv_path}")

    enricher = Enricher() if enrich else None
    funnel = Funnel()
    today = date.today().strftime("%d/%m/%Y")

    new_rows: list[dict[str, str]] = []
    by_domain: dict[str, int] = {s: 0 for s in selected}
    by_keyword_agg: dict[tuple[str, str], dict] = {}

    # Per-sub-domain commercial-valid target, seeded from the live catalog.
    existing_valid = valid_counts_by_subdomain(csv_path)
    valid_now = {s: existing_valid.get(s, 0) for s in selected}
    target = cfg.target_per_subdomain

    shots = _build_shots(cfg, selected)
    active = [s for s in selected if shots[s]]
    deadline = started + max_minutes * 60 if max_minutes else None
    used_backends: set[str] = set()
    # Circuit-breaker state: consecutive empty shots per backend, and the set of
    # backends retired for the rest of this run.
    empty_streak: dict[str, int] = {}
    dead_backends: set[str] = set()
    shots_run = 0
    appended = 0

    def _capped() -> bool:
        return cfg.target_total is not None and len(new_rows) >= cfg.target_total

    def _expired() -> bool:
        return deadline is not None and clock() >= deadline

    def _subdomain_full(sd: str) -> bool:
        return target is not None and valid_now[sd] >= target

    def _agg(sd: str, kw: str) -> dict:
        return by_keyword_agg.setdefault(
            (sd, kw), {"domain": sd, "keyword": kw, "hits": 0, "new": 0})

    def _prepare(cand, sd: str, kw: str):
        """Gates + dedup + liveness + row build. Returns the row, or None if dropped."""
        res = cand.result
        funnel.hit(sd)
        _agg(sd, kw)["hits"] += 1

        host_res = gates.classify_host(res, cfg)
        if host_res is not None and not host_res.kept:
            funnel.drop(sd, host_res.stage, host_res.host)
            return None
        # Kept-but-restricted (restricted_policy: "flag"): admitted for ingestion to
        # adjudicate per-URL, never as an assertion that it is licensed.
        flagged = host_res if host_res is not None else None
        text = f"{res.title} {res.snippet}"
        if gates.off_topic(text, cfg):
            funnel.drop(sd, gates.OFF_TOPIC, "")
            return None
        # The topicality floor is scoped to the broad backends (see
        # QualitySettings.relevance_backends): the dataset APIs are already bound to
        # the query and their titles are too terse to clear a vocab floor.
        scope = cfg.quality.relevance_backends
        if not scope or cand.backend in scope:
            on_topic, _hits = gates.keyword_relevance(text, vocab.get(sd, ()), cfg)
            if not on_topic:
                funnel.drop(sd, gates.LOW_RELEVANCE, "")
                return None
        if not dedup.take(res.link):
            funnel.duplicate(sd)
            return None
        if (cfg.verify_liveness and cand.backend not in API_BACKENDS
                and not gates.is_live(res.link)):
            funnel.drop(sd, gates.DEAD, "")
            return None

        row = build_row(res, sd, today=today, domain_vocab=vocab,
                        country_hints=cfg.country_hints)
        for col, val in cand.metadata_row().items():
            if val and not row.get(col):
                row[col] = val

        # Country gate. Applied here, after build_row, because Country is derived
        # from the link + text and a backend may override it with real metadata
        # (ckan's `country: India`), so this is the first point it is knowable.
        if not gates.country_ok(row, cfg):
            funnel.drop(sd, gates.WRONG_COUNTRY, "")
            return None

        if flagged is not None:
            # Never let a backend's metadata licence stand in for a restricted
            # host's terms: blank it so the row is Unknown and ingestion's deep
            # check is the thing that decides. Counted only now, once the row has
            # survived every other gate, so the tally reflects rows actually kept.
            row["License"] = ""
            note = row.get("Note") or ""
            row["Note"] = (f"{gates.RESTRICTED_NOTE} ({flagged.detail}). {note}").strip()
            funnel.restricted_flagged(flagged.host)

        funnel.candidate(sd)
        return row

    def _enrich_one(row: dict) -> None:
        try:
            enricher.enrich(row)
        except Exception as e:            # noqa: BLE001 - best-effort by contract
            logger.debug(f"source: enrich failed for {row.get('Dataset Link')}: {e}")

    def _enrich_batch(rows: list[dict]) -> None:
        """Resolve a real licence for the unknown-licence rows, concurrently.

        Enrichment is a network round-trip per row (the HF/GitHub API, or a HEAD
        plus licence detection), so doing it inline made every shot cost one
        round-trip per candidate. The legacy engine ran this on a thread pool and
        dropping it was a throughput regression — ``cfg.workers`` restores it.
        ``Enricher`` is safe to share across threads (it guards its GitHub
        rate-limit flag with a lock).
        """
        if enricher is None or not cfg.enrich_unknown or not rows:
            return
        todo = [r for r in rows if license_verdict(r.get("License")) == "unknown"]
        if not todo:
            return
        with ThreadPoolExecutor(max_workers=max(1, cfg.workers)) as pool:
            list(pool.map(_enrich_one, todo))

    def _accept(row: dict, sd: str, kw: str) -> None:
        """Licence gate + record the row (enrichment already happened in batch)."""
        verdict = gates.resolve_license(row, cfg, None)
        funnel.verdict(verdict)
        if verdict == "blocked":
            return
        if cfg.license_policy == "commercial_only" and verdict != "ok":
            return

        final_sd = row.get("Sub-Domain", sd)      # refine_domain may reassign it
        new_rows.append(row)
        by_domain[final_sd] = by_domain.get(final_sd, 0) + 1
        if verdict == "ok":
            valid_now[final_sd] = valid_now.get(final_sd, 0) + 1
        _agg(sd, kw)["new"] += 1
        lic = str(row.get("License") or "").strip() or "unknown"
        logger.info(f"source: [{sd}] {len(new_rows)}/{cfg.target_total or '*'} "
                    f"lic={lic} + {row['Name']} :: {row['Dataset Link']}")

    try:
        while active and not _capped() and not _expired() and shots_run < _MAX_SHOTS:
            for sd in list(active):
                if _capped() or _expired():
                    break
                if _subdomain_full(sd) or not shots[sd]:
                    active.remove(sd)
                    continue
                bname, kw = shots[sd].popleft()
                if bname in dead_backends:        # circuit-broken earlier this run
                    continue
                shots_run += 1
                backend = get_backend(bname)
                if backend is None or not backend.available(cfg):
                    # Missing credentials / no base_url: it can never produce, so
                    # retire it now instead of re-checking once per keyword.
                    dead_backends.add(bname)
                    logger.info(f"source: backend {bname} is unavailable "
                                f"(disabled, or missing config/credentials) — skipping")
                    continue
                used_backends.add(bname)
                bc = cfg.backends.get(bname)
                limit = bc.per_keyword_limit if bc else 50
                t0 = clock()
                try:
                    cands = backend.search(sd, kw, limit, cfg)
                except Exception as e:                # noqa: BLE001 - one shot never aborts the run
                    logger.warning(f"source: backend {bname} failed for {kw!r}: {e}")
                    cands = []
                took = clock() - t0

                # Circuit breaker: a backend that keeps coming back empty is either
                # unreachable (data.gov.in times out on every request from some
                # networks) or unproductive for this keyword set. Either way, stop
                # paying its timeout once per keyword for the rest of the run.
                if cands:
                    empty_streak[bname] = 0
                else:
                    empty_streak[bname] = empty_streak.get(bname, 0) + 1
                    if empty_streak[bname] >= cfg.max_consecutive_empty:
                        dead_backends.add(bname)
                        logger.warning(
                            f"source: backend {bname} returned nothing "
                            f"{empty_streak[bname]}x in a row (last shot {took:.1f}s) "
                            f"— disabling it for the rest of this run")

                before = len(new_rows)
                pending: list[dict] = []
                for cand in cands:
                    if _capped() or _expired() or _subdomain_full(sd):
                        break
                    row = _prepare(cand, sd, kw)
                    if row is not None:
                        pending.append(row)
                _enrich_batch(pending)            # concurrent licence lookups
                for row in pending:
                    if _capped() or _subdomain_full(sd):
                        break
                    _accept(row, sd, kw)

                # One line per shot: without it a slow backend makes the run look
                # frozen (nothing else logs until a row is actually kept).
                logger.info(f"source: shot {shots_run} [{sd}] {bname} kw={kw!r} "
                            f"-> {len(cands)} hits, {len(new_rows) - before} kept "
                            f"in {took:.1f}s "
                            f"(total {len(new_rows)}/{cfg.target_total or '*'})")

                # Append the rows gathered this shot so a long run keeps its progress
                # (crash-safe: an interrupted run has already persisted every prior shot).
                batch = new_rows[before:]
                if batch and not dry_run:
                    appended += append_rows(csv_path, batch)
                if not shots[sd] or _subdomain_full(sd):
                    if sd in active:
                        active.remove(sd)
    finally:
        pass

    license_filled = sum(1 for r in new_rows if str(r.get("License") or "").strip())
    funnel.appended = appended
    elapsed_s = round(clock() - started, 1)

    stamp = f"{date.today():%Y%m%d}"
    review_csv = out_csv or os.path.join(LOGS, "discovered", f"discovered-{stamp}.csv")
    _write_csv(new_rows, review_csv)

    target_reached = (target is not None and all(valid_now[s] >= target for s in selected)) \
        or (cfg.target_total is not None and len(new_rows) >= cfg.target_total) \
        or (target is None and cfg.target_total is None)

    summary = {
        "found": funnel.found, "new": len(new_rows), "appended": appended,
        "funnel": funnel.as_dict(), "csv": review_csv,
        "domains": selected, "target": cfg.target_total,
        "target_per_domain": target, "target_reached": target_reached,
        "by_domain": by_domain, "by_keyword": list(by_keyword_agg.values()),
        "backends": sorted(used_backends), "engines": cfg.backends.get("searxng").engines
        if cfg.backends.get("searxng") else "",
        "elapsed_s": elapsed_s, "max_minutes": max_minutes,
        "license_filled": license_filled,
        "license_rate": round(license_filled / len(new_rows), 3) if new_rows else 0.0,
    }
    _write_summary(summary, os.path.join(LOGS, "discovered", f"summary-{stamp}.json"))
    logger.info(f"source: done in {elapsed_s}s - {len(new_rows)} new, "
                f"{appended} appended, {license_filled} licensed")
    return summary
