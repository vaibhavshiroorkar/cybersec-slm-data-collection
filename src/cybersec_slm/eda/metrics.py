#!/usr/bin/env python3
"""Corpus metrics for the EDA stage (the diagram's parallel validations).

Single streaming pass over the cleaned corpus computes: volumetric counts,
source balance + the worst single-source concentration per subdomain, text-quality
stats, an exact-duplicate audit, and the subdomain distribution used for
run-to-run drift. Pure stdlib so it stays cheap to run on every batch.
"""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from statistics import mean, median

from ..cleaning.common import find_input_files, text_of
from ..core import iter_jsonl


def compute_metrics(input_dir: str) -> dict:
    """Walk ``input_dir`` (cleaned jsonl tree) and return the metrics dict."""
    total = 0
    empty = 0
    per_sub: Counter[str] = Counter()
    per_source: dict[str, Counter[str]] = defaultdict(Counter)
    char_counts: list[int] = []
    token_counts: list[int] = []
    seen: set[str] = set()
    dups = 0

    for ap, sub, source, _rel in find_input_files(input_dir):
        for rec in iter_jsonl(ap):
            if rec.get("_parse_error"):
                continue
            total += 1
            per_sub[sub] += 1
            per_source[sub][source] += 1
            t = text_of(rec)
            if not t:
                empty += 1
                continue
            char_counts.append(len(t))
            token_counts.append(len(t.split()))
            h = hashlib.sha256(t.encode("utf-8")).hexdigest()
            if h in seen:
                dups += 1
            else:
                seen.add(h)

    # worst single-source share within any subdomain (concentration risk)
    worst = {"worst_share": 0.0, "subdomain": None, "source": None}
    for sub, srcs in per_source.items():
        sub_total = per_sub[sub] or 1
        for src, n in srcs.items():
            share = n / sub_total
            if share > worst["worst_share"]:
                worst = {"worst_share": share, "subdomain": sub, "source": src}

    text_total = len(char_counts)
    dist = {sub: per_sub[sub] / total for sub in per_sub} if total else {}
    return {
        "total": total,
        "empty_text": empty,
        "empty_rate": (empty / total) if total else 0.0,
        "num_subdomains": len(per_sub),
        "subdomains": dict(per_sub),
        "subdomain_distribution": dist,
        "num_sources": sum(len(s) for s in per_source.values()),
        "concentration": worst,
        "dup_rate": (dups / text_total) if text_total else 0.0,
        "text_quality": {
            "avg_chars": round(mean(char_counts), 1) if char_counts else 0.0,
            "avg_tokens": round(mean(token_counts), 1) if token_counts else 0.0,
            "median_tokens": median(token_counts) if token_counts else 0,
            "min_tokens": min(token_counts) if token_counts else 0,
        },
    }
