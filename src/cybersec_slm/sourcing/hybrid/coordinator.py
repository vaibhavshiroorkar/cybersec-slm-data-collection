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
"""

from __future__ import annotations

import csv
import sys
from collections import Counter
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

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, dry_run: bool = False, limit: int | None = None) -> int:
        """
        Run the hybrid sourcer.

        dry_run:  print the plan and backend order, do not write anything.
        limit:    stop after this many NEW rows (for testing).

        Returns the total number of rows in the catalog after the run.
        """
        cfg = self.cfg
        effective_target = min(cfg.target, (limit or cfg.target))

        self._log(f"\n{'='*60}")
        self._log(f"Hybrid Sourcer – {cfg.name}")
        self._log(f"  Field     : {cfg.field}")
        self._log(f"  Target    : {effective_target:,} rows")
        self._log(f"  Output    : {cfg.output_csv}")
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

        # Step 5: Final write + report
        self._write_csv(cfg.output_csv)
        self._print_final_report()
        return len(self._rows)

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
        """Filter candidates through quality gates and add passing rows."""
        cfg = self.cfg
        added = 0
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
