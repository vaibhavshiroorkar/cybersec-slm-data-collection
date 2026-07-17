#!/usr/bin/env python3
"""Test run: does the pipeline still work after a change?

Seeds a tiny synthetic corpus into a scratch data root and drives the real
stages over it -- clean, then the EDA gate, then schema, then the schema
validator -- reporting pass/fail and a duration for each.

Two properties make this worth having rather than just running the test suite:

**It cannot touch the corpus.** The parent (``control.start('test-run')``) creates
a scratch directory and spawns this with ``CYBERSEC_SLM_DATA_ROOT`` pointed at
it, so every path this process computes -- ``data/raw``, ``data/clean``,
``data/final``, ``logs/`` -- is inside the scratch root. Not "should not touch"
the real one: there is no code path from here to it. That matters because a smoke
test people are afraid to press is a smoke test nobody presses.

**It is offline and deterministic.** It does not fetch: 1,020 catalogued sources
behind a network is slow, rate-limited and flaky, and a health check that fails
for the third reason teaches nobody anything. Ingestion's own logic is covered by
the test suite; what this catches is the thing unit tests miss -- the stages not
composing, a settings change breaking a real run, an artifact not landing where
the next stage looks for it.

Invoked as::

    python -m cybersec_slm.dashboard.run_test <config.json>
"""

from __future__ import annotations

import json
import os
import sys
import time

from ..core import logger

# Enough records to clear the EDA gate's volume floor (config.MIN_TOTAL_RECORDS
# defaults to 50) without being slow. Real prose, because the cleaner drops
# anything under its length floor and the garbage-ratio check is not fooled by
# lorem ipsum.
SEED_RECORDS = 60

_SEED_TEXTS = (
    "A heap overflow in the packet parser allows remote code execution when a "
    "crafted frame is processed by the vulnerable service.",
    "Rotate service account keys every ninety days and revoke any key that has "
    "not been used within the last thirty days.",
    "SQL injection in the login form allows an attacker to read arbitrary rows "
    "from the credentials table using a union select payload.",
    "The incident response team isolated the affected host, captured volatile "
    "memory, and preserved disk images before beginning remediation.",
    "Cross site scripting in the comment field lets an attacker execute script "
    "in the context of another authenticated user's session.",
)


def _seed(root: str, domain: str) -> int:
    """Write a small raw corpus under ``root`` and return how many records."""
    folder = os.path.join(root, "data", "raw", domain, "testrun")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, "data.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        for i in range(SEED_RECORDS):
            rec = {
                "text": f"{_SEED_TEXTS[i % len(_SEED_TEXTS)]} (case {i})",
                "source": "testrun",
                "url": "https://example.invalid/testrun",
                "license": "MIT",
            }
            f.write(json.dumps(rec) + "\n")
    return SEED_RECORDS


def _run_stage(argv: list[str]) -> None:
    """Run one stage's CLI in-process, as run_all and run_fix do."""
    from .. import cli
    cli.main(argv)


def _validate() -> None:
    from ..cleaning.schema import validate_corpus
    valid, invalid = validate_corpus()
    if invalid:
        raise RuntimeError(f"{invalid} record(s) failed schema validation")
    if not valid:
        raise RuntimeError("no records reached the validator")


def _step(name: str, fn) -> dict:
    """Run one step, timing it, and turn any failure into a result rather than a
    crash: a Test run must always produce a report, especially when it fails."""
    started = time.time()
    try:
        fn()
        return {"step": name, "ok": True, "seconds": round(time.time() - started, 1),
                "detail": ""}
    except Exception as e:                       # noqa: BLE001
        logger.error(f"test run: {name} failed: {type(e).__name__}: {e}")
        return {"step": name, "ok": False, "seconds": round(time.time() - started, 1),
                "detail": f"{type(e).__name__}: {e}"}


def _first_subdomain() -> str:
    """A sub-domain the active taxonomy actually has.

    Hardcoding one would fail the moment the profile changed, and a health check
    that fails because of the health check is worse than none.
    """
    from ..sourcing import catalog
    names = list(catalog.subdomains(catalog.load()))
    return names[0] if names else "Network Security"


def main(argv: list[str] | None = None) -> None:
    args = list(argv if argv is not None else sys.argv[1:])
    if not args:
        raise SystemExit("run_test: expected a config file path")
    with open(args[0], encoding="utf-8") as f:
        cfg = json.load(f)

    from .. import core
    root = core.data_root()
    report_path = cfg.get("report") or os.path.join(root, "logs", "test_run.json")
    domain = _first_subdomain()

    logger.info(f"test run: scratch root {root}")
    started = time.time()
    steps = [_step("seed", lambda: _seed(root, domain))]

    # Each stage as its own step, so a report names the one that broke rather than
    # saying the run failed. --no-enforce on eda: a 60-record corpus fails the
    # sufficiency gate by construction, and this is testing that the stage runs,
    # not that a toy corpus is publishable.
    if steps[-1]["ok"]:
        steps.append(_step("clean", lambda: _run_stage(["clean", "--workers", "1"])))
        steps.append(_step("eda", lambda: _run_stage(["eda", "--no-enforce"])))
        steps.append(_step("schema", lambda: _run_stage(["schema"])))
        steps.append(_step("validate", _validate))

    dataset = os.path.join(root, "data", "final", "dataset.jsonl")
    records = 0
    if os.path.exists(dataset):
        with open(dataset, encoding="utf-8", errors="replace") as f:
            records = sum(1 for ln in f if ln.strip())

    report = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "seconds": round(time.time() - started, 1),
        "ok": all(s["ok"] for s in steps),
        "steps": steps,
        "seeded": SEED_RECORDS,
        "records_out": records,
        "subdomain": domain,
        "scratch": root,
    }
    os.makedirs(os.path.dirname(report_path) or ".", exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    logger.info(f"test run: {'PASS' if report['ok'] else 'FAIL'} in "
                f"{report['seconds']}s; {records} record(s) reached the dataset "
                f"-> {report_path}")


if __name__ == "__main__":
    main(sys.argv[1:])
