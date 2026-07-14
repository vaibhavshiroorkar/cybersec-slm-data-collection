"""run_all: the dashboard's sequential source->...->schema orchestrator."""

import json

import pytest

from cybersec_slm import cli
from cybersec_slm.dashboard import run_all
from cybersec_slm.eda import SufficiencyError


def _write_plan(tmp_path, stage_keys):
    p = tmp_path / "plan.json"
    p.write_text(json.dumps([[key] for key in stage_keys]), encoding="utf-8")
    return str(p)


ALL = ["source", "ingest", "clean", "eda", "schema"]


def test_runs_stages_in_plan_order(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "main", lambda argv: calls.append(argv[0]))
    run_all.main([_write_plan(tmp_path, ALL)])
    assert calls == ALL


def test_sourcing_failure_is_non_fatal(tmp_path, monkeypatch):
    calls = []

    def fake_main(argv):
        if argv[0] == "source":
            raise RuntimeError("SearXNG offline")
        calls.append(argv[0])

    monkeypatch.setattr(cli, "main", fake_main)
    run_all.main([_write_plan(tmp_path, ALL)])       # must not raise
    assert calls == ["ingest", "clean", "eda", "schema"]


def test_eda_gate_halts_remaining_stages(tmp_path, monkeypatch):
    calls = []

    def fake_main(argv):
        calls.append(argv[0])
        if argv[0] == "eda":
            raise SufficiencyError("not enough data")

    monkeypatch.setattr(cli, "main", fake_main)
    run_all.main([_write_plan(tmp_path, ALL)])       # halts gracefully, no raise
    assert calls == ["source", "ingest", "clean", "eda"]     # schema never runs


def test_a_stage_failure_other_than_source_propagates(tmp_path, monkeypatch):
    def fake_main(argv):
        if argv[0] == "ingest":
            raise RuntimeError("boom")

    monkeypatch.setattr(cli, "main", fake_main)
    with pytest.raises(RuntimeError):
        run_all.main([_write_plan(tmp_path, ["source", "ingest", "clean"])])


def test_missing_plan_argument_raises(tmp_path, monkeypatch):
    with pytest.raises(SystemExit):
        run_all.main([])
