#!/usr/bin/env python3
"""Domain balance checker — counts records per cybersecurity domain and
reports imbalance so you can prevent the SLM from over-fitting to one area.

Reads data/clean/ and produces:
  - A console table sorted by record count
  - logs/balance_report.csv

Warnings are raised when any domain has >IMBALANCE_RATIO x the median count.
Pass cap=N to hard-limit each domain (useful before splitting).

    from cybersec_slm.cleaning.balance import check_balance, apply_cap
    check_balance()               # report only
    apply_cap(max_per_domain=50_000)   # cap + rewrite data/clean/
"""

from __future__ import annotations

import csv
import os
import random

from ..core import CLEAN_DATA, JsonlWriter, iter_jsonl, logger

IMBALANCE_RATIO = 5.0   # warn if max/median exceeds this


def _count_domain(input_dir: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in os.scandir(input_dir):
        if not entry.is_dir():
            continue
        domain = entry.name
        n = 0
        for root, _dirs, files in os.walk(entry.path):
            for fn in files:
                if not fn.endswith(".jsonl"):
                    continue
                with open(os.path.join(root, fn), "rb") as f:
                    n += sum(1 for ln in f if ln.strip())
        counts[domain] = n
    return counts


def check_balance(input_dir: str = CLEAN_DATA,
                  report_dir: str | None = None) -> dict[str, int]:
    """Count records per domain, log a table, write CSV, return counts dict."""
    if not os.path.isdir(input_dir):
        logger.warning(f"balance: {input_dir} not found — run cleaning first")
        return {}

    counts = _count_domain(input_dir)
    if not counts:
        logger.warning("balance: no domains found")
        return {}

    total = sum(counts.values())
    sorted_counts = sorted(counts.items(), key=lambda x: -x[1])
    values = sorted(counts.values())
    mid = len(values) // 2
    median = values[mid] if len(values) % 2 else (values[mid - 1] + values[mid]) // 2
    max_count = values[-1]

    logger.info("=" * 60)
    logger.info(f"{'Domain':<45} {'Records':>8} {'%':>6}")
    logger.info("-" * 60)
    for domain, cnt in sorted_counts:
        pct = 100 * cnt / total if total else 0
        flag = " ⚠ heavy" if median and cnt > IMBALANCE_RATIO * median else ""
        logger.info(f"{domain:<45} {cnt:>8,} {pct:>5.1f}%{flag}")
    logger.info("-" * 60)
    logger.info(f"{'TOTAL':<45} {total:>8,} {'100.0%':>6}")
    logger.info("=" * 60)

    if median and max_count > IMBALANCE_RATIO * median:
        heavy = [d for d, c in counts.items() if c > IMBALANCE_RATIO * median]
        logger.warning(
            f"balance: imbalance detected — {heavy} have >{IMBALANCE_RATIO}x the "
            f"median ({median:,}). Consider apply_cap() before splitting."
        )

    rdir = report_dir or os.path.join(os.path.dirname(input_dir), "logs")
    os.makedirs(rdir, exist_ok=True)
    path = os.path.join(rdir, "balance_report.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain", "records", "pct"])
        for domain, cnt in sorted_counts:
            w.writerow([domain, cnt, f"{100 * cnt / total:.2f}"])
        w.writerow(["TOTAL", total, "100.00"])
    logger.info(f"balance report -> {path}")
    return counts


def apply_cap(max_per_domain: int, input_dir: str = CLEAN_DATA,
              seed: int = 42) -> dict[str, int]:
    """Randomly downsample any domain exceeding max_per_domain records.

    Rewrites data/clean/ files in-place. The random seed ensures reproducibility.
    Returns the new counts dict.
    """
    rng = random.Random(seed)
    counts = _count_domain(input_dir)
    new_counts: dict[str, int] = {}

    for entry in os.scandir(input_dir):
        if not entry.is_dir():
            continue
        domain = entry.name
        total = counts.get(domain, 0)
        if total <= max_per_domain:
            new_counts[domain] = total
            continue

        logger.info(f"  cap {domain}: {total:,} -> {max_per_domain:,}")
        # Collect all records, shuffle, keep first max_per_domain.
        all_recs: list[dict] = []
        src_files: list[str] = []
        for root, _dirs, files in os.walk(entry.path):
            for fn in sorted(files):
                if not fn.endswith(".jsonl"):
                    continue
                p = os.path.join(root, fn)
                src_files.append(p)
                all_recs.extend(iter_jsonl(p))

        rng.shuffle(all_recs)
        kept = all_recs[:max_per_domain]

        # Measure original sizes BEFORE truncating (truncating first would zero
        # every size and collapse the whole domain into the first file).
        sizes = {src: (os.path.getsize(src) or 1) for src in src_files}
        total_size = max(sum(sizes.values()), 1)
        for src in src_files:
            open(src, "w").close()
        idx = 0
        for i, src in enumerate(src_files):
            if idx >= len(kept):
                break
            # last file takes the remainder so rounding never drops records
            share = (len(kept) - idx if i == len(src_files) - 1
                     else round(len(kept) * sizes[src] / total_size))
            w = JsonlWriter(src)
            for rec in kept[idx: idx + share]:
                w.write(rec)
            w.close()
            idx += share
        new_counts[domain] = min(total, max_per_domain)

    logger.info(f"apply_cap done: max_per_domain={max_per_domain:,}")
    return new_counts


def _count_jsonl(path: str) -> int:
    with open(path, "rb") as f:
        return sum(1 for ln in f if ln.strip())


def _rewrite_sampled(files: list[str], keep: list[dict]) -> None:
    """Rewrite `files` in place holding `keep`, split proportional to old sizes.

    Sizes are read BEFORE truncating (truncate-first would zero every size and
    dump all records into the first file). The last file absorbs the remainder so
    rounding never drops a record.
    """
    sizes = {src: (os.path.getsize(src) or 1) for src in files}
    total_size = max(sum(sizes.values()), 1)
    for src in files:
        open(src, "w").close()
    idx = 0
    for i, src in enumerate(files):
        if idx >= len(keep):
            break
        share = (len(keep) - idx if i == len(files) - 1
                 else round(len(keep) * sizes[src] / total_size))
        w = JsonlWriter(src)
        for rec in keep[idx: idx + share]:
            w.write(rec)
        w.close()
        idx += share


def apply_source_cap(max_source_share: float = 0.6, input_dir: str = CLEAN_DATA,
                     *, margin: float = 0.9, seed: int = 42) -> dict[str, dict[str, int]]:
    """Downsample any source that exceeds `max_source_share` of its subdomain.

    Only acts on subdomains with >= 2 sources — a single-source subdomain cannot
    be un-concentrated by capping. For each over-represented subdomain the largest
    source is downsampled (repeatedly, so a second over-large source is caught) to
    ``target_share/(1-target_share) * others`` records, where ``target_share`` is
    ``max_source_share * margin`` so the result lands *below* the ceiling with a
    little headroom. Only the capped source's own files are rewritten, preserving
    every other source's records and the source->directory attribution the
    concentration metric relies on.

    Returns ``{subdomain: {source: new_count}}`` for the sources that were capped.
    """
    if not os.path.isdir(input_dir):
        logger.warning(f"balance: {input_dir} not found — run cleaning first")
        return {}
    rng = random.Random(seed)
    target_share = max(min(max_source_share * margin, 0.95), 0.05)
    changed: dict[str, dict[str, int]] = {}

    for sub_entry in os.scandir(input_dir):
        if not sub_entry.is_dir():
            continue
        src_files: dict[str, list[str]] = {}
        src_counts: dict[str, int] = {}
        for src_entry in os.scandir(sub_entry.path):
            if not src_entry.is_dir():
                continue
            files, n = [], 0
            for root, _dirs, fns in os.walk(src_entry.path):
                for fn in sorted(fns):
                    if fn.endswith(".jsonl"):
                        p = os.path.join(root, fn)
                        files.append(p)
                        n += _count_jsonl(p)
            if files and n:
                src_files[src_entry.name] = files
                src_counts[src_entry.name] = n
        if len(src_counts) < 2:
            continue  # single source: capping cannot reduce its 100% share

        for _ in range(len(src_counts)):
            total = sum(src_counts.values())
            top = max(src_counts, key=src_counts.get)
            if src_counts[top] <= max_source_share * total:
                break
            others = total - src_counts[top]
            target = max(int(target_share / (1 - target_share) * others), 1)
            if target >= src_counts[top]:
                break
            all_recs: list[dict] = []
            for p in src_files[top]:
                all_recs.extend(iter_jsonl(p))
            rng.shuffle(all_recs)
            _rewrite_sampled(src_files[top], all_recs[:target])
            logger.info(f"  source-cap {sub_entry.name}/{top}: "
                        f"{src_counts[top]:,} -> {target:,}")
            changed.setdefault(sub_entry.name, {})[top] = target
            src_counts[top] = target

    logger.info(f"apply_source_cap done: max_source_share={max_source_share:.0%}")
    return changed
