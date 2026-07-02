#!/usr/bin/env python3
"""Cleaning orchestrator (thin CLI wrapper around the pipeline)."""

from __future__ import annotations

import sys

from . import pipeline
from .common import logger

STAGES = {"sanitize", "dedup", "pii", "lang"}


def run(cmd: str, limit: int | None = None) -> None:
    """Run a cleaning diagnostic: sanitize | dedup | pii | lang | report | balance.

    Production cleaning is the parallel per-source worker (`cybersec-slm run` /
    `all`); this command is for inspecting one transform in isolation. Single-stage
    runs write to data/_stages/<stage>/; report recounts the output trees; balance
    reports per-domain record counts.
    """
    if cmd in STAGES:
        pipeline.run_single_stage(cmd, limit=limit)
    elif cmd == "report":
        pipeline.build_report_from_outputs()
    elif cmd == "balance":
        from .balance import check_balance
        check_balance()
    else:
        raise ValueError(f"unknown cleaning command: {cmd}")
    logger.info("=== CLEANING DONE ===")


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "report"
    limit = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else None
    run(cmd, limit)


if __name__ == "__main__":
    main()
