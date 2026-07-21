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
    """The EDA sufficiency gate halts the main run; the orchestrator then hands
    control to the auto-fix loop rather than running schema directly.

    The fix loop's first action is an observing EDA (``--no-enforce``), so the
    fake only raises for an *enforced* EDA. The main run's EDA is enforced, so it
    raises and schema never runs from the main plan; the fix loop's EDA is
    no-enforce, so it records the call without raising and the loop proceeds.
    """
    calls = []

    def fake_main(argv):
        calls.append(argv[0])
        if argv[0] == "eda" and "--no-enforce" not in argv:
            raise SufficiencyError("not enough data")

    monkeypatch.setattr(cli, "main", fake_main)
    run_all.main([_write_plan(tmp_path, ALL)])       # halts gracefully, no raise
    # The main plan ran source -> ingest -> clean -> eda (enforced, raised), and
    # schema never ran from it. The orchestrator then entered the auto-fix loop.
    assert calls[:4] == ["source", "ingest", "clean", "eda"]
    assert "schema" not in calls[:4]                 # schema is not in the main plan's tail
    assert calls[4:]                                 # the auto-fix loop took over
    assert calls[4] == "eda"                         # fix loop starts with an observing EDA


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
