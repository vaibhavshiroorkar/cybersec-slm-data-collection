#!/usr/bin/env python3
"""EDA orchestrator — validations -> drift -> sufficiency gate -> persisted run.

    Cleaned corpus
      -> compute_metrics (volume / balance / concentration / quality / dup audit)
      -> drift vs the previous run (subdomain distribution delta)
      -> topic balance evaluation (v2: CV + min-share + feedback)
      -> sufficiency gate (blockers stop the run; warnings are logged + tracked)
      -> auto-rebalance (v2: cap over-represented subdomains if enabled)
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

from ..core import CLEAN_DATA, LOGS, logger
from . import config
from .metrics import compute_metrics

EDA_DIR = os.path.join(LOGS, "eda")


class SufficiencyError(RuntimeError):
    """Raised when a blocker-severity gate violation should stop the pipeline."""


def _default_input() -> str:
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


def compute_vocab_drift(input_dir: str, prev: dict | None) -> dict:
    """Compute n-gram/vocabulary drift compared to the previous run."""
    import collections
    from ..cleaning.common import find_input_files, text_of
    from ..core import iter_jsonl

    vocab: collections.Counter = collections.Counter()
    total = 0
    for ap, sub, source, _rel in find_input_files(input_dir):
        for rec in iter_jsonl(ap):
            if rec.get("_parse_error"):
                continue
            text = text_of(rec).lower()
            tokens = [t for t in text.split() if t.isalnum()]
            vocab.update(tokens)
            total += len(tokens)

    current_dist = {k: v / total for k, v in vocab.items()} if total else {}
    if not prev or "vocab_distribution" not in prev.get("metrics", {}):
        return {"available": False, "max_drift": 0.0, "distribution": current_dist}

    prev_dist = prev["metrics"]["vocab_distribution"]
    keys = set(current_dist) | set(prev_dist)
    drift_score = sum(abs(current_dist.get(k, 0.0) - prev_dist.get(k, 0.0)) for k in keys) / 2.0
    return {"available": True, "max_drift": round(drift_score, 4), "distribution": current_dist}


def _per_subdomain_concentration(metrics: dict) -> dict:
    """Worst single-source share per subdomain.

    Prefers the full ``per_subdomain_concentration`` map from metrics; falls back
    to the single overall ``concentration`` entry for older metric payloads.
    """
    per = metrics.get("per_subdomain_concentration")
    if per:
        return per
    c = metrics.get("concentration") or {}
    return {c["subdomain"]: c} if c.get("subdomain") else {}


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

    # Source concentration check: now a BLOCKER to prevent data poisoning via flooding.
    for sub, c in _per_subdomain_concentration(metrics).items():
        if c["worst_share"] <= config.MAX_SOURCE_SHARE:
            continue
        add("blocker", "concentration",
            f"source '{c['source']}' is {c['worst_share']:.0%} of subdomain "
            f"'{sub}' (> {config.MAX_SOURCE_SHARE:.0%} ceiling) — "
            f"suspected flooding vector.")

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

    vocab_drift = metrics.get("vocab_drift", {})
    if vocab_drift.get("available") and vocab_drift.get("max_drift", 0.0) > config.MAX_DRIFT:
        add("blocker", "vocab_drift",
            f"vocabulary shift detected: {vocab_drift['max_drift']:.2f} "
            f"(> {config.MAX_DRIFT:.2f})")

    # ── v2: topic balance checks ─────────────────────────────────────────────
    topic_cv = metrics.get("topic_cv", 0.0)
    if topic_cv > config.MAX_TOPIC_CV:
        add("warning", "topic_balance",
            f"topic balance CV={topic_cv:.2f} (> {config.MAX_TOPIC_CV:.2f}); "
            f"corpus is heavily skewed across subdomains")

    # Any subdomain below the minimum share is a blocker
    total = metrics.get("total", 0)
    if total > 0:
        dist = metrics.get("subdomain_distribution", {})
        for sub, share in dist.items():
            if share < config.MIN_SUBDOMAIN_SHARE:
                add("warning", "subdomain_underrepresented",
                    f"subdomain '{sub}' has {share:.1%} of records "
                    f"(< {config.MIN_SUBDOMAIN_SHARE:.0%} minimum share)")

    return v


# ── v2: feedback generation ──────────────────────────────────────────────────

def _generate_feedback(metrics: dict) -> dict:
    """Generate actionable feedback from EDA metrics.

    The feedback section tells the operator *what to do* about imbalances,
    not just that they exist.
    """
    total = metrics.get("total", 0)
    subdomains = metrics.get("subdomains", {})
    dist = metrics.get("subdomain_distribution", {})
    per_sub_quality = metrics.get("per_subdomain_quality", {})

    feedback: dict = {
        "under_represented": [],
        "over_represented": [],
        "quality_concerns": [],
        "recommendations": [],
    }

    if not total or not subdomains:
        return feedback

    avg_count = total / len(subdomains) if subdomains else 0

    for sub, count in subdomains.items():
        share = dist.get(sub, 0.0)

        # Under-represented: <25% of average count or <MIN_SUBDOMAIN_SHARE
        if count < avg_count * 0.25 or share < config.MIN_SUBDOMAIN_SHARE:
            feedback["under_represented"].append({
                "subdomain": sub,
                "records": count,
                "share": round(share, 4),
                "target_records": int(avg_count),
                "suggestion": f"Add more sources for '{sub}' — "
                              f"currently {count} records ({share:.1%}), "
                              f"target ~{int(avg_count)} for balance",
            })

        # Over-represented: >4x average count
        if count > avg_count * 4:
            suggested_cap = int(avg_count * 2)
            feedback["over_represented"].append({
                "subdomain": sub,
                "records": count,
                "share": round(share, 4),
                "suggested_cap": suggested_cap,
                "suggestion": f"Consider capping '{sub}' from {count} to "
                              f"~{suggested_cap} records",
            })

    # Quality concerns per subdomain
    for sub, quality in per_sub_quality.items():
        avg_tokens = quality.get("avg_tokens", 0)
        if avg_tokens < config.MIN_AVG_TOKENS * 2:
            feedback["quality_concerns"].append({
                "subdomain": sub,
                "avg_tokens": avg_tokens,
                "suggestion": f"'{sub}' has low text quality "
                              f"(avg {avg_tokens:.0f} tokens); "
                              f"consider reviewing source selection",
            })

    # High-level recommendations
    if feedback["under_represented"]:
        feedback["recommendations"].append(
            f"{len(feedback['under_represented'])} subdomain(s) are under-represented "
            f"— add more sources or run `cybersec-slm source` to discover new ones"
        )
    if feedback["over_represented"]:
        feedback["recommendations"].append(
            f"{len(feedback['over_represented'])} subdomain(s) are over-represented "
            f"— consider `cybersec-slm clean balance --cap N` to rebalance"
        )
    topic_cv = metrics.get("topic_cv", 0.0)
    if topic_cv > config.MAX_TOPIC_CV:
        feedback["recommendations"].append(
            f"Topic balance CV={topic_cv:.2f} is high — the corpus is skewed. "
            f"Rebalancing will improve model coverage across cyber topics"
        )

    return feedback


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


# ── v2: auto-rebalance ───────────────────────────────────────────────────────

def _auto_rebalance(feedback: dict, input_dir: str) -> bool:
    """Cap over-represented subdomains and return True if any capping was done.

    ``apply_cap`` takes a global ``max_per_domain`` limit.  We compute the cap
    as 2× the average subdomain count so the most bloated subdomains shrink
    while the long tail is untouched.
    """
    over = feedback.get("over_represented", [])
    if not over:
        return False

    try:
        from ..cleaning.balance import apply_cap
    except ImportError:
        logger.warning("eda: auto-rebalance requested but cleaning.balance unavailable")
        return False

    # Use the minimum suggested cap across over-represented subdomains
    caps = [e["suggested_cap"] for e in over if e.get("suggested_cap")]
    if not caps:
        return False
    cap = min(caps)
    logger.info(f"eda: auto-rebalancing with cap={cap}")
    apply_cap(cap)
    return True


def run_eda(input_dir: str | None = None, *, enforce: bool = True,
            profile: bool = False) -> dict:
    """Run the validations + gate. Raises :class:`SufficiencyError` on a blocker
    when ``enforce`` (the loop-back signal); otherwise returns the report dict."""
    input_dir = input_dir or _default_input()
    logger.info(f"eda: scanning {input_dir}")
    metrics = compute_metrics(input_dir)
    prev = _previous_report()
    metrics["drift"] = compute_drift(metrics["subdomain_distribution"], prev)
    
    vocab_result = compute_vocab_drift(input_dir, prev)
    metrics["vocab_drift"] = {"available": vocab_result["available"], "max_drift": vocab_result["max_drift"]}
    metrics["vocab_distribution"] = vocab_result["distribution"]
    violations = evaluate_gate(metrics)
    feedback = _generate_feedback(metrics)
    blockers = [x for x in violations if x["severity"] == "blocker"]
    report = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "input_dir": input_dir,
        "passed": not blockers,
        "owner": config.OWNER,
        "metrics": metrics,
        "violations": violations,
        "feedback": feedback,
    }
    path = _persist(report)
    if profile:
        _profile(input_dir)

    logger.info(f"eda: total={metrics['total']} subdomains={metrics['num_subdomains']} "
                f"dup_rate={metrics['dup_rate']:.1%} "
                f"topic_cv={metrics.get('topic_cv', 0.0):.2f} "
                f"worst_concentration={metrics['concentration']['worst_share']:.0%} "
                f"-> {path}")
    for x in violations:
        (logger.error if x["severity"] == "blocker" else logger.warning)(
            f"eda {x['severity'].upper()} [{x['check']}]: {x['message']}")

    # v2: log feedback recommendations
    for rec in feedback.get("recommendations", []):
        logger.info(f"eda FEEDBACK: {rec}")

    # v2: auto-rebalance over-represented subdomains (cross-subdomain balance).
    # This caps a subdomain that dwarfs the others down to ~2x the average — a
    # bounded, sensible trim. Source *concentration within* a subdomain is left
    # to the opt-in `clean balance --source-share` tool, because auto-capping to
    # the ceiling destroys data whenever the secondary sources are small.
    if config.AUTO_REBALANCE and feedback.get("over_represented"):
        if _auto_rebalance(feedback, input_dir):
            logger.info("eda: auto-rebalance applied — re-computing metrics")
            recomputed = compute_metrics(input_dir)
            report["metrics_after_rebalance"] = recomputed
            report["rebalanced"] = True

            # Re-evaluate the gate to see if rebalancing cleared the blockers
            violations = evaluate_gate(recomputed)
            blockers = [x for x in violations if x["severity"] == "blocker"]
            report["violations"] = violations
            report["passed"] = not blockers

    if blockers and enforce:
        # Route outliers to manual review instead of just crashing
        import shutil
        from ..core import DATA_ROOT
        manual_review_dir = os.path.join(DATA_ROOT, "manual_review", f"run-{report['ts'].replace(':', '').replace('-', '')}")
        os.makedirs(manual_review_dir, exist_ok=True)
        try:
            shutil.move(input_dir, manual_review_dir)
            logger.warning(f"eda: Outliers routed to manual review queue at {manual_review_dir}")
        except Exception as e:
            logger.error(f"eda: Failed to route to manual review: {e}")
        raise SufficiencyError(
            f"EDA sufficiency gate FAILED: {len(blockers)} blocker(s); "
            f"owner={config.OWNER}; loop back to ingestion. Report: {path}")
    return report
