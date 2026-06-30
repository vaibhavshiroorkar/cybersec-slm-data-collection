#!/usr/bin/env python3
"""Prefect orchestration for the end-to-end corpus build.

The flow is a thin wrapper over the existing stage functions — it adds
scheduling, per-source isolation/retries/timeouts, secret loading, and the DVC
snapshot, but the actual work still lives in extraction/cleaning/eda/normalize.

    build_corpus:
        load_secrets
        -> extract_clean_source.map(descriptors)   # per-source, allowlist-gated,
        |                                             retried, timed out
        -> cross_source_dedup
        -> eda_gate            # blocker -> SufficiencyError -> flow fails (loop back)
        -> normalize_corpus    # writes dataset.jsonl + manifest
        -> dvc_snapshot        # version + push the release (optional)

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
    from ..extraction import sources
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
def extract_clean_source(descriptor: dict) -> dict:
    """Fetch + clean ONE source into data/clean/ (allowlist-gated in the worker)."""
    from ..core import CLEAN_DATA
    from ..extraction import worker
    return worker.process_source(descriptor, data_root=DATA_ROOT,
                                 clean_data_dir=CLEAN_DATA)


@task
def cross_source_dedup() -> dict:
    from ..cleaning.pipeline import final_global_dedup
    return final_global_dedup()


@task
def eda_gate(enforce: bool = True) -> dict:
    """Run the EDA sufficiency gate. Raises SufficiencyError on a blocker."""
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
    """End-to-end: extract+clean per source -> dedup -> EDA gate -> normalize -> DVC."""
    present = load_secrets()
    logger.info(f"orchestration: secrets present for {present}")

    descriptors = _load_descriptors(sources_spec)
    logger.info(f"orchestration: {len(descriptors)} sources")

    if _HAS_PREFECT:
        results = [f.result() for f in extract_clean_source.map(descriptors)]
    else:
        results = [extract_clean_source(d) for d in descriptors]
    ok = sum(1 for r in results if r.get("status") == "ok")
    skipped = sum(1 for r in results if r.get("status") == "skipped")
    logger.info(f"orchestration: extract+clean ok={ok} skipped={skipped} "
                f"failed={len(results) - ok - skipped}")

    cross_source_dedup()
    eda_gate(enforce_eda)              # SufficiencyError here fails the flow (loop back)
    report = normalize_corpus()
    if dvc_push:
        dvc_snapshot(push=True)
    return report


if __name__ == "__main__":
    build_corpus()
