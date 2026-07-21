#!/usr/bin/env python3
"""Driver that grows a catalog from one or more bulk-harvest backends.

Mirrors the shape of search-based discovery (:mod:`cybersec_slm.sourcing.run`):
read the existing catalog to dedup, gather candidates round-robin across the
selected sub-domains so coverage stays even, and append the survivors in batches
so a long run keeps its progress. The difference is the *source* of candidates — a
paginated CKAN ``package_search`` (or any registered backend) instead of a SearXNG
keyword sweep, and the license stamped from the spec rather than fetched per
source — so a harvest reaches thousands of license-clean rows in the time discovery
takes to enrich a hundred.

A run is bounded by ``target_total`` (the spec's total-row goal) and optionally a
per-backend ``max_results`` over-fetch. It stops when the catalog reaches the target
or every backend's queries are exhausted. ``dry_run`` writes only the candidate
review CSV and a summary, never the catalog.

The funnel (``found`` / ``quality_dropped`` / ``duplicates`` / ``appended`` /
``by_domain``) lands in ``logs/discovered/harvest-<date>.json`` with the same shape
the dashboard reads for a discovery run, so a harvest shows up alongside search
runs without a separate UI.

Public API:
    run_harvest(profile=None, *, dry_run=False, target_total=None, client=None) -> dict
"""

from __future__ import annotations

import csv
import json
import os
from collections import deque
from collections.abc import Callable
from datetime import date

from ...core import LOGS, logger
from ..row import SHEET_COLUMNS, row_to_list
from ..sheet import append_rows, existing_links, normalize_url
from ..stats import Funnel
from . import base
from . import spec as spec_mod


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


def _row_link(row: dict) -> str:
    return normalize_url(row.get("Dataset Link") or "")


def _dedup_key(row: dict, spec: dict) -> str:
    """Stable identity for a harvested row: the spec's ``dedup_by`` field, else the
    normalized link.

    A CKAN ``resource_id`` (the resource UUID) is more stable than the kebab slug
    for catching the same dataset linked two ways; the link is the fallback so a
    spec without a dedup field still works. The driver dedups against both the
    existing catalog (by link) and this-run's seen set (by ``dedup_by`` when set).
    """
    field = (spec.get("dedup_by") or "").strip()
    if field == "resource_id":
        # The row's Note carries the direct data URL; the catalog link is the
        # resource landing page. CKAN resource id is not on the row directly, so
        # fall through to the link for now — kept as a hook for a richer backend.
        pass
    return _row_link(row)


def run_harvest(profile: str | None = None, *, dry_run: bool = False,
                target_total: int | None = None, client=None,
                clock: Callable[[], float] | None = None) -> dict:
    """Grow the catalog from the profile's harvest spec; return a summary dict.

    ``profile`` selects whose ``harvest.yaml`` runs (default: the active profile).
    ``target_total`` overrides the spec's ``target_total`` (a CLI ``--target``).
    ``client`` is an optional shared ``httpx.Client`` for connection reuse across
    pages; ``clock`` is an injectable monotonic time source for tests.

    Returns ``{"found", "quality_dropped", "duplicates", "appended", "csv",
    "target_total", "target_reached", "by_domain", "elapsed_s"}``.
    """
    import time as _time

    started = (clock or _time.monotonic)()
    from .. import profiles
    # Materialize the profile dir + harvest.yaml (idempotent, never overwrites
    # edits) so the spec file exists for the user to tweak, even on a profile
    # that was created before harvest support landed.
    profiles.ensure(profile)
    csv_path = profiles.catalog_path(profile)
    harvest_spec = spec_mod.load(profile) or {}

    target = int(target_total if target_total is not None
                 else (harvest_spec.get("target_total") or 0)) or None
    backends = harvest_spec.get("backends") or []
    if not backends:
        logger.warning("harvest: no backends configured in the spec; nothing to do")
        backends = []

    logger.info(f"harvest: target_total={target}; {len(backends)} backend(s); "
                f"catalog={csv_path}")
    existing = existing_links(csv_path)
    logger.info(f"harvest: {len(existing)} links already in the catalog")

    new_rows: list[dict[str, str]] = []
    seen: set[str] = set()
    funnel = Funnel()
    by_domain: dict[str, int] = {}

    def _capped() -> bool:
        return target is not None and len(new_rows) >= target

    # Round-robin across backends: build a queue of (spec, backend) and pull one
    # row from each in turn, so a slow backend does not starve the others and a
    # single backend's first-page results land evenly. Each backend's generator
    # is drained lazily, so we never materialize a whole catalog in memory.
    queue: deque = deque()
    for b in backends:
        name = (b.get("name") or "").strip()
        if not name:
            continue
        try:
            backend = base.get(name)
        except KeyError as e:
            logger.warning(f"harvest: {e}")
            continue
        try:
            gen = iter(backend.harvest(b, client=client))
        except Exception as e:                                  # noqa: BLE001
            logger.warning(f"harvest: backend {name!r} failed to start: {e}")
            continue
        queue.append((name, gen, b))

    while queue and not _capped():
        name, gen, b = queue.popleft()
        try:
            row = next(gen)
        except StopIteration:
            continue
        except Exception as e:                                  # noqa: BLE001
            logger.warning(f"harvest: backend {name!r} raised: {e}")
            continue
        funnel.hit(row.get("Sub-Domain") or "")
        link = _row_link(row)
        if not link or link in existing:
            funnel.duplicate(row.get("Sub-Domain") or "")
            queue.append((name, gen, b))
            continue
        key = _dedup_key(row, b)
        if key in seen:
            funnel.duplicate(row.get("Sub-Domain") or "")
            queue.append((name, gen, b))
            continue
        seen.add(key)
        existing.add(link)
        funnel.candidate(row.get("Sub-Domain") or "")
        new_rows.append(row)
        d = row.get("Sub-Domain") or ""
        by_domain[d] = by_domain.get(d, 0) + 1
        if len(new_rows) % 100 == 0:
            logger.info(f"harvest: {len(new_rows)} new rows gathered"
                        + (f" / {target}" if target else ""))
        # Re-queue this backend to drain it round-robin with the rest, unless the
        # cap is hit (checked at the top of the loop).
        queue.append((name, gen, b))

    target_reached = target is not None and len(new_rows) >= target

    # Batch append (atomic, header-safe) unless dry-run.
    stamp = f"{date.today():%Y%m%d}"
    review_csv = os.path.join(LOGS, "discovered", f"harvested-{stamp}.csv")
    _write_csv(new_rows, review_csv)
    logger.info(f"harvest: wrote {len(new_rows)} candidate rows -> {review_csv}")

    appended = 0
    if new_rows and not dry_run:
        appended = append_rows(csv_path, new_rows)
        logger.info(f"harvest: appended {appended} rows to {csv_path}")
    else:
        logger.info("harvest: dry-run, not appending to the catalog")

    funnel.appended = appended
    elapsed_s = round((clock or _time.monotonic)() - started, 1)
    logger.info(f"harvest: done in {elapsed_s}s - {len(new_rows)} new, "
                f"{appended} appended")

    summary = {
        "found": funnel.found,
        "duplicates": funnel.duplicates,
        "candidates": funnel.candidates,
        "appended": appended,
        "csv": review_csv,
        "target_total": target,
        "target_reached": target_reached,
        "by_domain": by_domain,
        "elapsed_s": elapsed_s,
        "dry_run": dry_run,
    }
    _write_summary(summary, os.path.join(LOGS, "discovered",
                                          f"harvest-summary-{stamp}.json"))
    return summary
