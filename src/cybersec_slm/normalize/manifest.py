#!/usr/bin/env python3
"""Provenance manifest — a "datasheet for datasets" for every release.

Each ``dataset.jsonl`` is shipped with ``data/final/manifest.json`` so the
downstream annotation/training teams are never handed a blob with no pedigree
(threat model Output/Handoff: "Downstream Context Blindsidedness"). The manifest
records source origins + counts, the SPDX license breakdown, an EDA distribution
snapshot, the pipeline version + git commit, and a content fingerprint of the
dataset file — enough to scope/rollback a contaminated batch surgically rather
than discarding the whole corpus.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from collections import Counter

from ..core import LOGS, iter_jsonl, logger, sha256_file
from .enrich import pipeline_version
from .pipeline import DATASET, FINAL

MANIFEST = os.path.join(FINAL, "manifest.json")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


def _git_commit() -> str | None:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=_REPO_ROOT,
                             capture_output=True, text=True, timeout=10)
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def _eda_snapshot() -> dict | None:
    # LOGS, not <root>/logs: logs are per-profile now, and joining the root by hand
    # would read whichever profile happened to be built first.
    path = os.path.join(LOGS, "eda", "latest.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            rep = json.load(f)
        m = rep.get("metrics", {})
        return {"ts": rep.get("ts"), "passed": rep.get("passed"),
                "total": m.get("total"),
                "subdomain_distribution": m.get("subdomain_distribution"),
                "dup_rate": m.get("dup_rate"),
                "concentration": m.get("concentration")}
    except (ValueError, OSError):
        return None


def build_manifest(dataset_path: str | None = None) -> dict:
    """Aggregate a dataset.jsonl into a provenance manifest dict."""
    dataset_path = dataset_path or DATASET
    by_domain: Counter[str] = Counter()
    by_subdomain: Counter[str] = Counter()
    by_source: Counter[str] = Counter()
    by_license: Counter[str] = Counter()
    by_format: Counter[str] = Counter()
    by_record_type: Counter[str] = Counter()
    by_lang: Counter[str] = Counter()
    hashes: set[str] = set()
    total = tokens = chars = 0

    if os.path.exists(dataset_path):
        for rec in iter_jsonl(dataset_path):
            if rec.get("_parse_error"):
                continue
            total += 1
            by_domain[rec.get("domain_name", "?")] += 1
            by_subdomain[rec.get("subdomain_name", "?")] += 1
            by_source[rec.get("source", "?")] += 1
            by_license[rec.get("license") or "unspecified"] += 1
            by_format[rec.get("origin_format", "?")] += 1
            by_record_type[rec.get("record_type", "?")] += 1
            by_lang[rec.get("lang", "?")] += 1
            if rec.get("content_hash"):
                hashes.add(rec["content_hash"])
            tokens += int(rec.get("token_count") or 0)
            chars += int(rec.get("char_count") or 0)

    return {
        "dataset": os.path.basename(dataset_path),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "pipeline_version": pipeline_version(),
        "git_commit": _git_commit(),
        "record_count": total,
        "unique_content_hashes": len(hashes),
        "dataset_sha256": sha256_file(dataset_path) if os.path.exists(dataset_path) else None,
        "token_total": tokens,
        "char_total": chars,
        "domains": dict(by_domain),
        "subdomains": dict(by_subdomain.most_common()),
        "sources": dict(by_source.most_common()),
        "licenses": dict(by_license.most_common()),
        "origin_formats": dict(by_format.most_common()),
        "record_types": dict(by_record_type.most_common()),
        "languages": dict(by_lang.most_common()),
        "eda": _eda_snapshot(),
    }


def write_manifest(dataset_path: str | None = None, out: str | None = None) -> str:
    """Build + write the manifest next to the dataset. Returns its path."""
    manifest = build_manifest(dataset_path)
    out = out or MANIFEST
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    logger.info(f"normalize: provenance manifest -> {out} "
                f"({manifest['record_count']} records, "
                f"{len(manifest['licenses'])} licenses)")
    return out

