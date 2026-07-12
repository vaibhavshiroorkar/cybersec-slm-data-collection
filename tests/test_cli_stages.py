#!/usr/bin/env python3
"""CLI exposes a subcommand per stage; `run` is gone; `all` takes the union."""

from __future__ import annotations

import pytest

from cybersec_slm.cli import build_parser


def test_ingest_accepts_stage_flags():
    args = build_parser().parse_args(
        ["ingest", "--workers", "4", "--sources", "x.csv", "--resume"])
    assert args.stage == "ingest"
    assert args.workers == 4
    assert args.sources == "x.csv"
    assert args.resume is True


def test_all_accepts_sources_and_workers():
    args = build_parser().parse_args(["all", "--sources", "x.csv", "--workers", "2"])
    assert args.stage == "all"
    assert args.sources == "x.csv"
    assert args.workers == 2


def test_run_subcommand_is_removed():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["run"])


def test_clean_action_is_optional_for_the_stage():
    args = build_parser().parse_args(["clean"])
    assert args.stage == "clean"
    assert args.action is None
    assert args.purge_raw is False       # raw is kept by default


def test_clean_still_accepts_diagnostic_actions():
    args = build_parser().parse_args(["clean", "dedup"])
    assert args.stage == "clean"
    assert args.action == "dedup"


def test_schema_alias_parses_to_normalize_handler():
    args = build_parser().parse_args(["schema"])
    assert args.stage in ("schema", "normalize")
