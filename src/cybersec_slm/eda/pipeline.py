#!/usr/bin/env python3
"""EDA orchestrator — validations -> drift -> sufficiency gate -> persisted run.

    Cleaned corpus
      -> compute_metrics (volume / balance / concentration / quality / dup audit)
      -> drift vs the previous run (subdomain distribution delta)
      -> sufficiency gate (blockers stop the run; warnings are logged + tracked)
      -> persist logs/eda/run-<ts>.json (versioned for run-to-run diffing)
      -> [pass -> advance to normalize] or [blocker -> SufficiencyError -> loop back]

Per-run metrics are append-only history so drift is auditable across iterations
(threat model Stage 3: convert disposable reports into versioned lifecycle files).
"""

from __future__ import annotations

import glob
import json
import os
import time

from ..core import CLEAN_DATA, CLEANED, LOGS, logger
from . import config
from .metrics import compute_metrics

EDA_DIR = os.path.join(LOGS, "eda")


class SufficiencyError(RuntimeError):
    """Raised when a blocker-severity gate violation should stop the pipeline."""


def _default_input() -> str:
    if os.path.isdir(CLEAN_DATA) and any(os.scandir(CLEAN_DATA)):
        return CLEAN_DATA
    if os.path.isdir(CLEANED) and any(os.scandir(CLEANED)):
        return CLEANED
    return CLEAN_DATA


def _previous_report() -> dict | None:
    files = sorted(glob.glob(os.path.join(EDA_DIR, "run-*.json")))
    if not files:
        return None
    try:
        with open(files[-1], encoding="utf-8") as f:
            return json.load(f)
    except (ValueError, OSError):
        return None


def compute_drift(dist: dict, prev: dict | None) -> dict:
    """Max absolute subdomain-share change vs the previous run's distribution."""
    if not prev:
        return {"available": False, "max_delta": 0.0, "subdomain": None}
    prev_dist = prev.get("metrics", {}).get("subdomain_distribution", {})
    keys = set(dist) | set(prev_dist)
    deltas = {k: abs(dist.get(k, 0.0) - prev_dist.get(k, 0.0)) for k in keys}
    sub, delta = max(deltas.items(), key=lambda kv: kv[1], default=(None, 0.0))
    return {"available": True, "max_delta": round(delta, 4), "subdomain": sub,
            "per_subdomain": {k: round(v, 4) for k, v in deltas.items()}}


def evaluate_gate(metrics: dict) -> list[dict]:
    """Return gate violations; each is {severity: blocker|warning, check, message}."""
    v: list[dict] = []

    def add(sev, check, msg):
        v.append({"severity": sev, "check": check, "message": msg})

    if metrics["total"] < config.MIN_TOTAL_RECORDS:
        add("blocker", "volume",
            f"only {metrics['total']} records (< {config.MIN_TOTAL_RECORDS})")

    for sub, n in metrics["subdomains"].items():
        if n < config.MIN_RECORDS_PER_SUBDOMAIN:
            add("warning", "subdomain_volume",
                f"subdomain '{sub}' has {n} records (< {config.MIN_RECORDS_PER_SUBDOMAIN})")

    c = metrics["concentration"]
    if c["worst_share"] > config.MAX_SOURCE_SHARE:
        add("blocker", "concentration",
            f"source '{c['source']}' is {c['worst_share']:.0%} of subdomain "
            f"'{c['subdomain']}' (> {config.MAX_SOURCE_SHARE:.0%} ceiling)")

    if metrics["dup_rate"] > config.MAX_DUP_RATE:
        add("warning", "duplicates",
            f"exact-dup rate {metrics['dup_rate']:.0%} (> {config.MAX_DUP_RATE:.0%})")

    if metrics["text_quality"]["avg_tokens"] < config.MIN_AVG_TOKENS:
        add("warning", "text_quality",
            f"avg tokens {metrics['text_quality']['avg_tokens']} "
            f"(< {config.MIN_AVG_TOKENS})")

    drift = metrics.get("drift", {})
    if drift.get("available") and drift.get("max_delta", 0.0) > config.MAX_DRIFT:
        add("warning", "drift",
            f"subdomain '{drift['subdomain']}' share moved {drift['max_delta']:.0%} "
            f"vs the previous run (> {config.MAX_DRIFT:.0%})")

    return v


def _persist(report: dict) -> str:
    os.makedirs(EDA_DIR, exist_ok=True)
    path = os.path.join(EDA_DIR, f"run-{report['ts'].replace(':', '').replace('-', '')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    with open(os.path.join(EDA_DIR, "latest.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return path


def _profile(input_dir: str) -> None:
    """Optional ydata-profiling HTML report (best-effort; needs the `eda` extra)."""
    try:
        import pandas as pd
        from ydata_profiling import ProfileReport

        from ..cleaning.common import find_input_files, text_of
        from ..core import iter_jsonl
        rows = []
        for ap, sub, source, _rel in find_input_files(input_dir):
            for rec in iter_jsonl(ap):
                if rec.get("_parse_error"):
                    continue
                t = text_of(rec)
                rows.append({"subdomain": sub, "source": source,
                             "chars": len(t), "tokens": len(t.split())})
        if not rows:
            return
        df = pd.DataFrame(rows)
        out = os.path.join(EDA_DIR, "profile.html")
        ProfileReport(df, title="Cybersec corpus EDA", minimal=True).to_file(out)
        logger.info(f"eda: ydata-profiling report -> {out}")
    except Exception as ex:        # heavy/optional — never block the gate on it
        logger.debug(f"eda: profiling skipped ({type(ex).__name__}: {ex})")


def run_eda(input_dir: str | None = None, *, enforce: bool = True,
            profile: bool = False) -> dict:
    """Run the validations + gate. Raises :class:`SufficiencyError` on a blocker
    when ``enforce`` (the loop-back signal); otherwise returns the report dict."""
    input_dir = input_dir or _default_input()
    logger.info(f"eda: scanning {input_dir}")
    metrics = compute_metrics(input_dir)
    metrics["drift"] = compute_drift(metrics["subdomain_distribution"],
                                     _previous_report())
    violations = evaluate_gate(metrics)
    blockers = [x for x in violations if x["severity"] == "blocker"]
    report = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "input_dir": input_dir,
        "passed": not blockers,
        "owner": config.OWNER,
        "metrics": metrics,
        "violations": violations,
    }
    path = _persist(report)
    if profile:
        _profile(input_dir)

    logger.info(f"eda: total={metrics['total']} subdomains={metrics['num_subdomains']} "
                f"dup_rate={metrics['dup_rate']:.1%} "
                f"worst_concentration={metrics['concentration']['worst_share']:.0%} "
                f"-> {path}")
    for x in violations:
        (logger.error if x["severity"] == "blocker" else logger.warning)(
            f"eda {x['severity'].upper()} [{x['check']}]: {x['message']}")

    if blockers and enforce:
        raise SufficiencyError(
            f"EDA sufficiency gate FAILED: {len(blockers)} blocker(s); "
            f"owner={config.OWNER}; loop back to ingestion. Report: {path}")
    return report
