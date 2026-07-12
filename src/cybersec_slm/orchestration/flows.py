#!/usr/bin/env python3
"""Prefect orchestration for the end-to-end corpus build.

The flow is a thin wrapper over the existing stage functions — it adds
scheduling, per-source isolation/retries/timeouts, secret loading, and the DVC
snapshot, but the actual work still lives in ingestion/cleaning/eda/normalize.

Flow structure:
    build_corpus:
        load_secrets
        -> extract_source.map(descriptors)   # per-source, license-gated,
        |                                      retried, timed out
        |                                      (fetch + light EDA only — no cleaning)
        -> aggregated_clean                   # sequential clean pass + deterministic
        |                                      cross-source dedup (final_global_dedup)
        -> deep_eda_gate                      # enhanced EDA with topic balance + feedback
        -> normalize_corpus                   # writes dataset.jsonl + manifest
        -> dvc_snapshot                       # version + push the release (optional)

Prefect is optional: the module imports without it (the decorators degrade to
no-ops) so the plain helpers stay unit-testable; ``build_corpus`` itself needs
Prefect only for the mapped/parallel run.
"""

from __future__ import annotations

import os
import shutil
import subprocess

from ..core import DATA_ROOT, FINAL_DATA, logger

try:
    from prefect import flow, task
    _HAS_PREFECT = True
except Exception:                       # prefect not installed -> no-op decorators
    _HAS_PREFECT = False

    def task(*dargs, **dkwargs):
        if dargs and callable(dargs[0]):
            return dargs[0]
        return lambda fn: fn

    def flow(*dargs, **dkwargs):
        if dargs and callable(dargs[0]):
            return dargs[0]
        return lambda fn: fn


# Secrets the stages read from the environment. In AWS these come from Secrets
# Manager (via prefect-aws blocks); locally from .env. Never embedded in the image.
SECRET_KEYS = ("NVD_API_KEY", "KAGGLE_API_TOKEN", "GOOGLE_SEARCH_API_KEY",
               "GOOGLE_SEARCH_ENGINE_ID")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


def _load_descriptors(spec: str | None = None) -> list[dict]:
    from ..ingestion import sources
    return sources.load_descriptors(spec or sources.DEFAULT_CATALOG)


# --------------------------------------------------------------------- tasks ---
@task(retries=1)
def load_secrets() -> list[str]:
    """Hydrate API-key env vars from AWS Secrets Manager when prefect-aws is set up.

    Best-effort: a missing block / no AWS is fine (falls back to .env / shell env).
    Returns the names of keys that are present after loading (never their values).
    """
    try:
        from prefect_aws import AwsSecret  # type: ignore
        for key in SECRET_KEYS:
            if os.environ.get(key):
                continue
            try:
                os.environ[key] = AwsSecret.load(key.lower().replace("_", "-")).read_secret()
            except Exception:
                pass
    except Exception:
        logger.debug("orchestration: prefect-aws not configured; using env/.env")
    return [k for k in SECRET_KEYS if os.environ.get(k)]


@task(retries=2, retry_delay_seconds=30, timeout_seconds=3600)
def extract_source(descriptor: dict) -> dict:
    """Fetch ONE source + run light EDA gate (no cleaning — that's aggregated later)."""
    from ..ingestion import worker
    return worker.process_source(descriptor, data_root=DATA_ROOT)


@task
def aggregated_clean() -> dict:
    """Sequential clean of data/raw/ then deterministic cross-source dedup."""
    from ..cleaning.pipeline import final_global_dedup
    from ..core import CLEAN_DATA
    from ..ingestion.parallel import clean_raw_tree
    result = clean_raw_tree()
    final_global_dedup(CLEAN_DATA, resume=False)
    return result


@task
def deep_eda_gate(enforce: bool = True) -> dict:
    """Run the enhanced EDA sufficiency gate with topic balance + feedback.

    Raises SufficiencyError on a blocker.
    """
    from ..eda import run_eda
    return run_eda(enforce=enforce)


@task
def normalize_corpus() -> dict:
    from ..normalize import run_normalization
    return run_normalization(resume=False)


def _dvc_snapshot(push: bool) -> None:
    if not shutil.which("dvc"):
        logger.warning("orchestration: dvc not installed; skipping snapshot")
        return
    cmd = (["dvc", "repro"] if os.path.exists(os.path.join(_REPO_ROOT, "dvc.yaml"))
           else ["dvc", "add", os.path.join(FINAL_DATA, "dataset.jsonl")])
    try:
        subprocess.run(cmd, cwd=_REPO_ROOT, check=True)
        if push:
            subprocess.run(["dvc", "push"], cwd=_REPO_ROOT, check=True)
        logger.info(f"orchestration: dvc snapshot done ({'pushed' if push else 'local'})")
    except (OSError, subprocess.SubprocessError) as ex:
        logger.error(f"orchestration: dvc snapshot failed ({ex})")


@task
def dvc_snapshot(push: bool = False) -> None:
    _dvc_snapshot(push)


# ---------------------------------------------------------------------- flow ---
@flow(name="build-corpus")
def build_corpus(sources_spec: str | None = None, *, enforce_eda: bool = True,
                 dvc_push: bool = False) -> dict:
    """End-to-end v2: ingest+lightEDA -> aggregated clean -> deep EDA -> normalize -> DVC."""
    present = load_secrets()
    logger.info(f"orchestration: secrets present for {present}")

    descriptors = _load_descriptors(sources_spec)
    logger.info(f"orchestration: {len(descriptors)} sources")

    # Phase 1: Parallel Ingest + Light EDA (fetch only, no cleaning)
    if _HAS_PREFECT:
        results = [f.result() for f in extract_source.map(descriptors)]
    else:
        results = [extract_source(d) for d in descriptors]
    ok = sum(1 for r in results if r.get("status") == "ok")
    skipped = sum(1 for r in results if r.get("status") == "skipped")
    rejected = sum(1 for r in results if r.get("status") == "rejected")
    logger.info(f"orchestration: ingest+lightEDA ok={ok} skipped={skipped} "
                f"rejected={rejected} failed={len(results) - ok - skipped - rejected}")

    # Phase 2: Aggregated Cleaning (sequential, full dedup)
    aggregated_clean()

    # Phase 3: Deep EDA Gate (topic balance + feedback)
    # SufficiencyError here fails the flow (loop back)
    deep_eda_gate(enforce_eda)

    # Phase 4: Schema Normalization
    report = normalize_corpus()
    if dvc_push:
        dvc_snapshot(push=True)
    return report


if __name__ == "__main__":
    build_corpus()
