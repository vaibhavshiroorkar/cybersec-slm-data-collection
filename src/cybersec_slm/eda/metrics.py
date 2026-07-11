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

    # v2: per-subdomain quality tracking
    sub_token_counts: dict[str, list[int]] = defaultdict(list)
    sub_char_counts: dict[str, list[int]] = defaultdict(list)

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
            nc = len(t)
            nt = len(t.split())
            char_counts.append(nc)
            token_counts.append(nt)
            sub_char_counts[sub].append(nc)
            sub_token_counts[sub].append(nt)
            h = hashlib.sha256(t.encode("utf-8")).hexdigest()
            if h in seen:
                dups += 1
            else:
                seen.add(h)

    # worst single-source share within any subdomain (concentration risk).
    # ``num_sources`` records how many sources the worst subdomain has: a
    # single-source subdomain cannot be un-concentrated by capping, so the gate
    # treats it as a warning rather than a hard blocker.
    worst = {"worst_share": 0.0, "subdomain": None, "source": None, "num_sources": 0}
    per_subdomain_concentration: dict[str, dict] = {}
    for sub, srcs in per_source.items():
        sub_total = per_sub[sub] or 1
        top_src, top_n = max(srcs.items(), key=lambda kv: kv[1])
        top_share = top_n / sub_total
        per_subdomain_concentration[sub] = {
            "worst_share": top_share, "source": top_src, "num_sources": len(srcs)}
        if top_share > worst["worst_share"]:
            worst = {"worst_share": top_share, "subdomain": sub, "source": top_src,
                     "num_sources": len(srcs)}

    text_total = len(char_counts)
    dist = {sub: per_sub[sub] / total for sub in per_sub} if total else {}

    # v2: topic balance — coefficient of variation across subdomain counts
    topic_cv = _coefficient_of_variation(list(per_sub.values())) if per_sub else 0.0

    # v2: per-subdomain text quality breakdown
    per_subdomain_quality = {}
    for sub in per_sub:
        tc = sub_token_counts.get(sub, [])
        cc = sub_char_counts.get(sub, [])
        per_subdomain_quality[sub] = {
            "records": per_sub[sub],
            "avg_tokens": round(mean(tc), 1) if tc else 0.0,
            "median_tokens": median(tc) if tc else 0,
            "avg_chars": round(mean(cc), 1) if cc else 0.0,
        }

    return {
        "total": total,
        "empty_text": empty,
        "empty_rate": (empty / total) if total else 0.0,
        "num_subdomains": len(per_sub),
        "subdomains": dict(per_sub),
        "subdomain_distribution": dist,
        "num_sources": sum(len(s) for s in per_source.values()),
        "concentration": worst,
        "per_subdomain_concentration": per_subdomain_concentration,
        "dup_rate": (dups / text_total) if text_total else 0.0,
        "text_quality": {
            "avg_chars": round(mean(char_counts), 1) if char_counts else 0.0,
            "avg_tokens": round(mean(token_counts), 1) if token_counts else 0.0,
            "median_tokens": median(token_counts) if token_counts else 0,
            "min_tokens": min(token_counts) if token_counts else 0,
        },
        # v2 additions
        "topic_cv": round(topic_cv, 3),
        "per_subdomain_quality": per_subdomain_quality,
    }


def _coefficient_of_variation(values: list[int | float]) -> float:
    """Coefficient of variation (std / mean). 0 = perfectly balanced."""
    if not values or len(values) < 2:
        return 0.0
    m = mean(values)
    if m == 0:
        return 0.0
    from statistics import stdev
    return stdev(values) / m
