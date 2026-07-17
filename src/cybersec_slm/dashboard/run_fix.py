#!/usr/bin/env python3
"""The EDA fix loop: source the starved sub-domains until the corpus balances.

The EDA gate reports a skewed corpus and stops. Acting on that means working out
which sub-domains are starved, finding sources for only those, fetching and
cleaning only what arrived, and looking again - repeatedly, because one round of
discovery rarely closes the gap. This runs that loop::

    eda --no-enforce            what is starved?
      -> balanced? stop
      -> source --domains <starved> --target-per-domain <parity>
         ingest --domains <starved> --resume
         clean  --domains <starved> --resume
      -> look again
    schema                      rebuild the dataset over the fuller corpus

Every stage runs in-process via ``cli.main``, exactly as :mod:`.run_all` does, so
each behaves like its own page's "Run this stage" and the whole run lands in one
``pipeline.<pid>.log`` that the live monitor follows and Stop kills as one tree.

:mod:`.rebalance` owns the decisions (what is starved, what to aim for, what a
round runs); this module owns the loop and when to stop. It stops on any of:

* the corpus balances,
* a round discovers no new catalog rows (the search is exhausted for those
  sub-domains, so more rounds cannot help),
* the round budget runs out.

Every EDA in the loop is ``--no-enforce``. An enforced gate raises
``SufficiencyError`` on a blocker, which would end the run at the first look -
the exact state the fix exists to repair. The gate still computes, persists and
logs its verdict; it just does not halt.

Invoked as::

    python -m cybersec_slm.dashboard.run_fix <fix.json>
"""

from __future__ import annotations

import json
import sys

from ..core import logger
from . import control, rebalance, settings_store
from .run_all import _record_run_log


def _run_stage(argv: list[str]) -> None:
    """Run one stage's CLI in-process. A seam, so the loop is testable."""
    from .. import cli
    cli.main(argv)


def _report() -> dict:
    """The EDA report the last gate run persisted."""
    from . import data
    return data.latest_eda() or {}


def _counts() -> dict[str, int]:
    """Commercial-valid catalog rows per Sub-Domain."""
    from ..sourcing.sheet import valid_counts_by_subdomain
    from . import data
    return valid_counts_by_subdomain(data.catalog_path())


def _load_cfg(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    if not isinstance(cfg, dict):
        raise ValueError(f"malformed fix config: {path}")
    return cfg


def _eda_argv(settings: dict) -> list[str]:
    """An observing EDA: it reports and persists, but never halts the run."""
    merged = {**settings_store.get_stage("eda"), **settings, "no_enforce": True}
    return control.stage_argv("eda", settings=merged)


def _schema_argv(settings: dict) -> list[str]:
    merged = {**settings_store.get_stage("schema"), **settings}
    return control.stage_argv("schema", settings=merged)


def main(argv: list[str] | None = None) -> None:
    args = list(argv if argv is not None else sys.argv[1:])
    if not args:
        raise SystemExit("run_fix: expected a fix config file path")
    _record_run_log()

    cfg = _load_cfg(args[0])
    rounds = int(cfg.get("rounds") or rebalance.DEFAULT_ROUNDS)
    step = int(cfg.get("step") or rebalance.DEFAULT_ROW_STEP)
    settings = dict(cfg.get("settings") or {})

    logger.info(f"eda fix: up to {rounds} round(s), step {step} rows/domain")
    worked = False

    for i in range(1, rounds + 1):
        _run_stage(_eda_argv(settings))
        report = _report()

        if rebalance.is_balanced(report):
            logger.info(f"eda fix: corpus is balanced after {i - 1} round(s)")
            break

        domains = rebalance.lacking(report)
        if not domains:
            # Not balanced, but nothing is starved: the spread is the problem and
            # sourcing cannot target it. Capping would fix the number by deleting
            # data, which this run does not do.
            logger.info("eda fix: no sub-domain is starved; nothing to source")
            break

        before = _counts()
        target = rebalance.row_target(before, domains, step)
        logger.info(f"eda fix: round {i}/{rounds}: filling {domains} "
                    f"to {target} rows/domain")

        for stage_argv in rebalance.plan_round(domains, target, settings):
            try:
                _run_stage(stage_argv)
            except Exception as exc:                      # noqa: BLE001
                if stage_argv[0] != "source":
                    raise
                # Non-fatal, as in run_all: a discovery service being down never
                # blocks the build. The round below then sees no new rows and the
                # loop ends cleanly rather than spinning.
                logger.warning(f"eda fix: sourcing failed ({exc}); continuing")
        worked = True

        after = _counts()
        if after == before:
            logger.info("eda fix: the round found no new sources for "
                        f"{domains}; the search is exhausted, stopping")
            break
    else:
        logger.info(f"eda fix: round budget ({rounds}) spent")

    # A fix run always leaves a usable dataset, balanced or not. The loop's last
    # look predates its last clean, so re-run the gate over the fuller corpus
    # before rebuilding.
    if worked:
        _run_stage(_eda_argv(settings))
    _run_stage(_schema_argv(settings))
    logger.info("eda fix: complete")


if __name__ == "__main__":
    main(sys.argv[1:])
