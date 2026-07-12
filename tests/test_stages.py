#!/usr/bin/env python3
"""Tests for the canonical five-stage registry (cybersec_slm.stages)."""

from __future__ import annotations

from cybersec_slm import stages


def test_five_stages_in_order():
    assert stages.stage_keys() == ["source", "ingest", "clean", "eda", "schema"]


def test_get_stage_label_and_cli():
    s = stages.get_stage("ingest")
    assert s.key == "ingest"
    assert s.label
    assert s.cli == "ingest"


def test_get_stage_unknown_raises():
    try:
        stages.get_stage("nope")
    except KeyError:
        return
    raise AssertionError("expected KeyError for an unknown stage key")


def test_phase_from_log_detects_clean_over_ingest():
    lines = ["ingest: fetched foo", "clean: in=10 out=8"]
    assert stages.phase_from_log(lines) == "clean"


def test_phase_from_log_furthest_wins_regardless_of_order():
    # schema marker present anywhere means the run reached schema.
    lines = ["schema normalization -> dataset", "ingest: fetched foo"]
    assert stages.phase_from_log(lines) == "schema"


def test_phase_from_log_starting_when_lines_but_no_marker():
    assert stages.phase_from_log(["some unrelated line"]) == "starting"


def test_phase_from_log_unknown_when_empty():
    assert stages.phase_from_log([]) == "unknown"
