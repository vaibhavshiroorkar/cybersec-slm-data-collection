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


def _build_shots(cfg: SourcingConfig, selected: list[str]) -> dict[str, deque]:
    """Per-sub-domain queue of ``(backend_name, keyword)`` shots, backend-priority order.

    Backends are ordered so real-metadata APIs fire before the low-signal SearXNG
    last-resort; within a backend the sub-domain's keywords are walked in order.
    """
    order = cfg.enabled_backends()
    shots: dict[str, deque] = {}
    for sd in selected:
        q: deque = deque()
        for bname in order:
            for kw in cfg.keywords.get(sd, []):
                q.append((bname, kw))
        shots[sd] = q
    return shots


def source(profile: str | None = None, *, cfg: SourcingConfig | None = None,
           subdomains: list[str] | None = None, max_total: int | None = None,
           target_per_subdomain: int | None = None, dry_run: bool = False,
           enrich: bool = True, backends: list[str] | None = None,
           verify_liveness: bool | None = None, out_csv: str | None = None,
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

    def _process(cand, sd: str, kw: str) -> None:
        res = cand.result
        funnel.hit(sd)
        _agg(sd, kw)["hits"] += 1

        drop = gates.classify_host(res, cfg)
        if drop is not None:
            funnel.drop(sd, drop.stage, drop.host)
            return
        if gates.off_topic(f"{res.title} {res.snippet}", cfg):
            funnel.drop(sd, gates.OFF_TOPIC, "")
            return
        if not dedup.take(res.link):
            funnel.duplicate(sd)
            return
        if (cfg.verify_liveness and cand.backend not in API_BACKENDS
                and not gates.is_live(res.link)):
            funnel.drop(sd, gates.DEAD, "")
            return

        funnel.candidate(sd)
        row = build_row(res, sd, today=today, domain_vocab=vocab)
        for col, val in cand.metadata_row().items():
            if val and not row.get(col):
                row[col] = val

        verdict = gates.resolve_license(row, cfg, enricher)
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
                shots_run += 1
                backend = get_backend(bname)
                if backend is None or not backend.available(cfg):
                    continue
                used_backends.add(bname)
                bc = cfg.backends.get(bname)
                limit = bc.per_keyword_limit if bc else 50
                try:
                    cands = backend.search(sd, kw, limit, cfg)
                except Exception as e:                # noqa: BLE001 - one shot never aborts the run
                    logger.warning(f"source: backend {bname} failed for {kw!r}: {e}")
                    cands = []
                before = len(new_rows)
                for cand in cands:
                    if _capped() or _expired() or _subdomain_full(sd):
                        break
                    _process(cand, sd, kw)
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
