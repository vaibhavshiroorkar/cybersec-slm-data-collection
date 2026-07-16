"""Quick finish: snapshot the corpus cleaned so far, then carry on cleaning."""

import json

from cybersec_slm.dashboard import control


def _stages(plan):
    return [argv[0] for argv in plan]


def test_plan_snapshots_then_resumes_cleaning(monkeypatch):
    """eda + schema over what is cleaned, THEN clean resumes, THEN a final pass."""
    monkeypatch.setattr(control.settings_store, "get_stage", lambda k: {})
    plan = control.build_quick_finish_plan()
    assert _stages(plan) == ["eda", "schema", "clean", "eda", "schema"]


def test_snapshot_eda_never_enforces_the_gate(monkeypatch):
    """A partial corpus fails the sufficiency gate by construction; enforcing it
    would end the run before it got back to cleaning."""
    monkeypatch.setattr(control.settings_store, "get_stage", lambda k: {})
    plan = control.build_quick_finish_plan()
    snapshot_eda, final_eda = plan[0], plan[3]
    assert "--no-enforce" in snapshot_eda
    assert "--no-enforce" not in final_eda      # the real gate still gates


def test_clean_resumes_so_the_snapshot_costs_no_recleaning(monkeypatch):
    monkeypatch.setattr(control.settings_store, "get_stage", lambda k: {})
    clean = control.build_quick_finish_plan()[2]
    assert clean[0] == "clean" and "--resume" in clean


def test_plan_carries_each_stage_settings(monkeypatch):
    """Stage settings still apply; a flag a stage does not accept falls away."""
    monkeypatch.setattr(control.settings_store, "get_stage",
                        lambda k: {"workers": 4} if k == "clean" else {})
    plan = control.build_quick_finish_plan()
    clean = plan[2]
    assert "--workers" in clean and "4" in clean
    assert "--workers" not in plan[0]           # eda takes no --workers


def test_start_quick_finish_writes_the_plan(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    monkeypatch.setattr(control.settings_store, "get_stage", lambda k: {})
    monkeypatch.setattr(control, "_spawn_detached", lambda cmd, root, logs: 4321)

    res = control.start("quick-finish")
    assert res["ok"] and res["pid"] == 4321

    with open(control._plan_file(), encoding="utf-8") as f:
        plan = json.load(f)
    assert _stages(plan) == ["eda", "schema", "clean", "eda", "schema"]
    assert control.status()["stage"] == "quick-finish"


def test_quick_finish_refuses_while_a_run_is_live(tmp_path, monkeypatch):
    """It must not race the clean pass it is trying to snapshot."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    monkeypatch.setattr(control, "status",
                        lambda: {"running": True, "pid": 99})
    res = control.start("quick-finish")
    assert res["ok"] is False and "already active" in res["error"]
