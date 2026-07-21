"""
coordinator.py – HybridSourcer

The main orchestration engine. Given a HybridConfig it:

  1. Loads the existing Sources.csv (or starts fresh)
  2. Injects seed_rows from the config
  3. Runs backends in priority order until target is reached
  4. Applies quality scoring to filter each batch
  5. Enforces country floor (if India% dips below bias, routes next batch
     to a more India-productive backend)
  6. Writes the updated catalog back to Sources.csv after every batch
  7. Prints a live progress summary

Usage (from cli.py or directly):
    from cybersec_slm.sourcing.hybrid import HybridSourcer, load_config
    cfg = load_config("sources/profiles/ubi/hybrid_config.yaml")
    sourcer = HybridSourcer(cfg)
    sourcer.run()

Sequential vs parallel:
    By default backends still run one after another (predictable, easiest to
    reason about rejection stats per backend). Pass `parallel=True` to run()
    to fetch from all planned backends concurrently instead — since each
    backend hits an independent API/rate-limit, wall-clock time drops from
    sum(latency) to roughly max(latency). Candidates are still *applied* to
    the catalog in the fixed backend_order (pattern → ckan → huggingface →
    github → arxiv → searxng) once every fetch has returned, so which backend
    "wins" a given slot near the target is unchanged from the sequential mode.
"""

from __future__ import annotations

import csv
import sys
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .backends import BACKEND_REGISTRY
from .backends.base import CSV_FIELDS
from .config import HybridConfig
from .scorer import passes_quality


class HybridSourcer:
    """Orchestrates multiple backends to fill a Sources.csv catalog."""

    def __init__(self, config: HybridConfig, verbose: bool = True):
        self.cfg = config
        self.verbose = verbose

        self._rows: list[dict[str, str]] = []
        self._seen_urls: set[str] = set()
        self._stats: dict[str, int] = Counter()   # backend → rows added
        self._rejected: dict[str, int] = Counter()  # reason → count
        self._lock = threading.Lock()  # guards _rows/_seen_urls/_stats/_rejected

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, dry_run: bool = False, limit: int | None = None,
           parallel: bool = False) -> int:
        """
        Run the hybrid sourcer.

        dry_run:  print the plan and backend order, do not write anything.
        limit:    stop after this many NEW rows (for testing).
        parallel: fetch from all planned backends concurrently instead of
                  one at a time (see module docstring).

        Returns the total number of rows in the catalog after the run.
        """
        cfg = self.cfg
        effective_target = min(cfg.target, (limit or cfg.target))

        self._log(f"\n{'='*60}")
        self._log(f"Hybrid Sourcer – {cfg.name}")
        self._log(f"  Field     : {cfg.field}")
        self._log(f"  Target    : {effective_target:,} rows")
        self._log(f"  Output    : {cfg.output_csv}")
        self._log(f"  Mode      : {'parallel' if parallel else 'sequential'}")
        self._log(f"{'='*60}")

        # Step 1: Load existing catalog
        self._load_csv(cfg.output_csv)
        self._log(f"  Existing  : {len(self._rows):,} rows in catalog")

        # Step 2: Inject seed rows
        seed_added = self._inject_seeds()
        if seed_added:
            self._log(f"  Seeds     : +{seed_added} rows injected")

        gap = effective_target - len(self._rows)
        if gap <= 0:
            self._log(f"\nCatalog already at/above target ({len(self._rows):,}). Nothing to do.")
            return len(self._rows)

        # Step 3: Backend plan
        backends_to_use = cfg.choose_backends(gap)
        self._log(f"\nBackend plan for gap={gap:,}:")
        for b in backends_to_use:
            self._log(f"  [{b}]")

        if dry_run:
            self._log("\n[DRY RUN] No rows will be written.")
            self._print_keyword_summary()
            return len(self._rows)

        # Step 4: Run backends
        if parallel:
            self._run_parallel(backends_to_use, effective_target)
        else:
            self._run_sequential(backends_to_use, effective_target)

        # Step 5: Final write + report
        self._write_csv(cfg.output_csv)
        self._print_final_report()
        return len(self._rows)

    # ------------------------------------------------------------------
    # Backend execution strategies
    # ------------------------------------------------------------------

    def _run_sequential(self, backends_to_use: list[str], effective_target: int) -> None:
        cfg = self.cfg
        for backend_name in backends_to_use:
            gap = effective_target - len(self._rows)
            if gap <= 0:
                break

            backend_cls = BACKEND_REGISTRY.get(backend_name)
            if backend_cls is None:
                self._log(f"  [WARN] Unknown backend '{backend_name}' — skipping")
                continue

            self._log(f"\n  Running [{backend_name}] — need {gap:,} more rows ...")
            backend = backend_cls()

            try:
                candidates = backend.fetch(
                    keywords=cfg.keywords,
                    needed=gap * 3,   # over-fetch to absorb quality rejections
                    seen_urls=self._seen_urls,
                    config=cfg,
                )
            except Exception as exc:
                self._log(f"  [ERROR] {backend_name} failed: {exc}")
                continue

            added = self._apply_batch(candidates, backend_name)
            self._log(f"  [{backend_name}] → {added} rows accepted "
                      f"({len(candidates)-added} rejected), "
                      f"total now {len(self._rows):,}")

            # Checkpoint: write after every backend completes
            self._write_csv(cfg.output_csv)

    def _run_parallel(self, backends_to_use: list[str], effective_target: int) -> None:
        """Fetch from every planned backend concurrently, then apply results
        in backend_order. Each backend still shares `_seen_urls` (guarded by
        `_lock`) so they don't duplicate each other's finds mid-flight; the
        gap used for `needed` is computed once up front rather than shrinking
        as each backend finishes, since backends run simultaneously and don't
        know about each other's progress."""
        cfg = self.cfg
        gap = effective_target - len(self._rows)
        if gap <= 0:
            return

        valid_backends = []
        for backend_name in backends_to_use:
            backend_cls = BACKEND_REGISTRY.get(backend_name)
            if backend_cls is None:
                self._log(f"  [WARN] Unknown backend '{backend_name}' — skipping")
                continue
            valid_backends.append(backend_name)

        self._log(f"\n  Fetching from {len(valid_backends)} backends concurrently "
                  f"— need {gap:,} more rows ...")

        results: dict[str, list[dict[str, str]]] = {}
        errors: dict[str, str] = {}

        def _fetch(name: str) -> tuple[str, list[dict[str, str]]]:
            backend = BACKEND_REGISTRY[name]()
            candidates = backend.fetch(
                keywords=cfg.keywords,
                needed=gap * 3,
                seen_urls=self._seen_urls,   # thread-safe: set.add is atomic under the GIL
                config=cfg,
            )
            return name, candidates

        with ThreadPoolExecutor(max_workers=max(1, len(valid_backends))) as pool:
            futures = {pool.submit(_fetch, name): name for name in valid_backends}
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    _, candidates = fut.result()
                    results[name] = candidates
                    self._log(f"  [{name}] fetched {len(candidates)} candidates")
                except Exception as exc:
                    errors[name] = str(exc)
                    self._log(f"  [ERROR] {name} failed: {exc}")

        # Apply in the same fixed priority order as sequential mode, so which
        # backend "wins" a near-target slot is unaffected by finishing order.
        for backend_name in valid_backends:
            candidates = results.get(backend_name)
            if not candidates:
                continue
            added = self._apply_batch(candidates, backend_name)
            self._log(f"  [{backend_name}] → {added} rows accepted "
                      f"({len(candidates)-added} rejected), "
                      f"total now {len(self._rows):,}")

        self._write_csv(cfg.output_csv)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_csv(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            self._log(f"  [INFO] {path} not found — starting fresh")
            return
        with open(p, encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                url = (row.get("Dataset Link") or "").strip()
                if url and url in self._seen_urls:
                    continue
                self._seen_urls.add(url)
                self._rows.append(row)

    def _write_csv(self, path: str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(self._rows)

    def _inject_seeds(self) -> int:
        added = 0
        for row in self.cfg.seed_rows:
            url = (row.get("Dataset Link") or "").strip()
            if url and url in self._seen_urls:
                continue
            self._seen_urls.add(url)
            self._rows.append(row)
            added += 1
        return added

    def _apply_batch(self, candidates: list[dict[str, str]],
                     backend_name: str) -> int:
        """Filter candidates through quality gates and add passing rows.
        Thread-safe: this is the only place `_rows`/`_stats`/`_rejected` are
        mutated after backend fetches, and in parallel mode it's called
        sequentially from the main thread once all fetches complete, so the
        lock here is a cheap safety net rather than a hot path."""
        cfg = self.cfg
        added = 0
        with self._lock:
            for row in candidates:
                url = (row.get("Dataset Link") or "").strip()
                # Already seen (backend may not have deduped perfectly)
                if url in self._seen_urls:
                    self._rejected["duplicate"] += 1
                    continue

                ok, reason = passes_quality(
                    name=row.get("Name", ""),
                    description=row.get("Description", ""),
                    url=url,
                    country=row.get("Country", ""),
                    config=cfg,
                )
                if not ok:
                    self._rejected[reason] += 1
                    continue

                self._seen_urls.add(url)
                self._rows.append(row)
                self._stats[backend_name] += 1
                added += 1

        return added

    def _country_stats(self) -> dict[str, int]:
        return Counter(r.get("Country", "Unknown") for r in self._rows)

    def _log(self, msg: str) -> None:
        if self.verbose:
            try:
                print(msg, flush=True)
            except UnicodeEncodeError:
                print(msg.encode("ascii", "replace").decode(), flush=True)

    def _print_keyword_summary(self) -> None:
        cfg = self.cfg
        self._log("\nKeywords per subdomain:")
        for sd, kws in cfg.keywords.items():
            self._log(f"  {sd}: {len(kws)} keywords")
            for kw in kws[:3]:
                self._log(f"    - {kw}")
            if len(kws) > 3:
                self._log(f"    ... ({len(kws)-3} more)")

    def _print_final_report(self) -> None:
        total = len(self._rows)
        cs = self._country_stats()
        sd_counts = Counter(r.get("Sub-Domain") for r in self._rows)

        self._log(f"\n{'='*60}")
        self._log(f"FINAL CATALOG: {total:,} rows")
        self._log(f"{'='*60}")

        self._log("\nCountry breakdown:")
        for country, cnt in sorted(cs.items(), key=lambda x: -x[1]):
            pct = cnt / total * 100 if total else 0
            self._log(f"  {country}: {cnt:,} ({pct:.1f}%)")

        self._log("\nSub-Domain breakdown:")
        for sd, cnt in sd_counts.most_common():
            self._log(f"  {sd}: {cnt:,}")

        self._log("\nRows added per backend:")
        for backend, cnt in self._stats.most_common():
            self._log(f"  [{backend}]: {cnt:,}")

        if self._rejected:
            self._log("\nRejections by reason:")
            for reason, cnt in Counter(self._rejected).most_common():
                self._log(f"  {reason}: {cnt:,}")