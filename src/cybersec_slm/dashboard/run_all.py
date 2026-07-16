#!/usr/bin/env python3
"""Sequential orchestrator for the dashboard's full pipeline run.

Runs the five stages in order - source -> ingest -> clean -> eda -> schema - by
executing each stage's CLI in-process (``cli.main``), so a stage behaves exactly
as its own page's "Run this stage" and every stage's log lands in one
``pipeline.<pid>.log`` (the live monitor and ``phase_from_log`` follow it, and Stop
kills this one process tree).

The plan - a JSON list of per-stage argv lists - is written by
``control.start('all', ...)`` (see ``control.build_full_plan``) with each stage's
saved advanced settings already merged with the Overview overrides. Invoked as::

    python -m cybersec_slm.dashboard.run_all <plan.json>

Sourcing is non-fatal: a discovery failure (e.g. SearXNG offline) is logged and
the run continues to ingest using the existing catalog. The EDA sufficiency gate
halts the remaining stages (as the headless ``run_v2_pipeline`` does).
"""

from __future__ import annotations

import json
import os
import sys

from .. import core
from ..core import logger

# Pointer file naming the current full run's log. The orchestrator writes its own
# log path here at startup so the dashboard can follow the run's log directly
# instead of guessing from pids (which differ under the Windows launcher) or
# newest-mtime (which the parallel clean workers' own logs would win).
RUN_LOG_POINTER = "active_run_log.txt"


def _record_run_log() -> None:
    """Write this orchestrator's log path to the pointer the dashboard reads."""
    if not core.LOG_FILE:
        return
    try:
        os.makedirs(core.LOGS, exist_ok=True)
        with open(os.path.join(core.LOGS, RUN_LOG_POINTER), "w", encoding="utf-8") as f:
            f.write(core.LOG_FILE)
    except OSError:
        pass


def _load_plan(path: str) -> list[list[str]]:
    with open(path, encoding="utf-8") as f:
        plan = json.load(f)
    if not isinstance(plan, list):
        raise ValueError(f"malformed plan file: {path}")
    return [list(argv) for argv in plan]


def main(argv: list[str] | None = None) -> None:
    from .. import cli, stages
    from ..eda import SufficiencyError

    args = list(argv if argv is not None else sys.argv[1:])
    if not args:
        raise SystemExit("run_all: expected a plan file path")
    _record_run_log()
    plan = _load_plan(args[0])

    total = len(plan)
    for i, stage_argv in enumerate(plan, start=1):
        if not stage_argv:
            continue
        key = stage_argv[0]
        # Emit the stage marker up front so the live monitor advances even when a
        # stage reports only to stdout (sourcing prints its summary, not to the log).
        try:
            marker = stages.get_stage(key).markers[0]
        except KeyError:
            marker = key
        logger.info(f"{marker} full run stage {i}/{total}: {' '.join(stage_argv)}")
        try:
            cli.main(stage_argv)
        except SufficiencyError as exc:
            logger.error(str(exc))
            logger.error("full run halted at the EDA sufficiency gate - address "
                         "the blockers above and re-run.")
            return
        except Exception as exc:                       # noqa: BLE001
            if key == "source":
                # Non-fatal: a missing discovery service never blocks the build.
                logger.warning(f"full run: sourcing failed ({exc}); continuing "
                               "with the existing catalog")
                continue
            raise
    logger.info(f"full run complete ({total} stages)")


if __name__ == "__main__":
    main(sys.argv[1:])
