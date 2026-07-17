"""The EDA fix loop: source the starved sub-domains until the corpus balances.

Every stage is faked, so no test sources, fetches or cleans anything. What is
under test is the loop's shape: what it runs, and when it stops.
"""

import json

import pytest

from cybersec_slm.dashboard import run_fix


@pytest.fixture
def cfg(tmp_path):
    p = tmp_path / "fix.json"
    p.write_text(json.dumps({"rounds": 4, "step": 25, "settings": {}}),
                 encoding="utf-8")
    return str(p)


@pytest.fixture
def harness(monkeypatch):
    """Record the stages run, and script the EDA reports each round sees."""
    state = {"ran": [], "reports": [], "counts": [], "round": 0}

    def _run_stage(argv):
        state["ran"].append(list(argv))

    def _report():
        i = min(state["round"], len(state["reports"]) - 1)
        return state["reports"][i]

    def _counts():
        i = min(state["round"], len(state["counts"]) - 1)
        state["round"] += 1
        return state["counts"][i]

    monkeypatch.setattr(run_fix, "_run_stage", _run_stage)
    monkeypatch.setattr(run_fix, "_report", _report)
    monkeypatch.setattr(run_fix, "_counts", _counts)
    monkeypatch.setattr(run_fix, "_record_run_log", lambda: None)
    monkeypatch.setattr(run_fix.settings_store, "get_stage", lambda k: {})
    return state


def _rep(subs, topic_cv=0.0):
    total = sum(subs.values())
    return {"metrics": {"total": total, "subdomains": dict(subs),
                        "subdomain_distribution": {k: v / total
                                                   for k, v in subs.items()},
                        "topic_cv": topic_cv}}


def _stages(state):
    return [argv[0] for argv in state["ran"]]


# ------------------------------------------------------ the loop's shape -------
def test_a_balanced_corpus_does_no_rounds_and_still_rebuilds_the_dataset(harness,
                                                                          cfg):
    harness["reports"] = [_rep({"A": 1000, "B": 1000})]
    harness["counts"] = [{"A": 50, "B": 50}]

    run_fix.main([cfg])

    # One eda to look, then straight to schema. No sourcing: nothing is starved.
    assert _stages(harness) == ["eda", "schema"]


def test_a_starved_subdomain_is_sourced_ingested_and_cleaned(harness, cfg):
    harness["reports"] = [_rep({"A": 5000, "B": 10}), _rep({"A": 5000, "B": 5000})]
    harness["counts"] = [{"A": 100, "B": 5}, {"A": 100, "B": 60}]

    run_fix.main([cfg])

    assert _stages(harness) == ["eda", "source", "ingest", "clean",
                                "eda", "eda", "schema"]
    src = harness["ran"][1]
    assert "--domains" in src and "B" in src
    assert "A" not in src                      # A is not starved; do not touch it


def test_the_loop_stops_as_soon_as_the_corpus_balances(harness, cfg):
    harness["reports"] = [_rep({"A": 5000, "B": 10}), _rep({"A": 5000, "B": 5000})]
    harness["counts"] = [{"A": 100, "B": 5}, {"A": 100, "B": 60}]

    run_fix.main([cfg])

    # Round 2's eda sees balance, so only one round of sourcing happens.
    assert _stages(harness).count("source") == 1


def test_the_loop_gives_up_after_the_configured_rounds(harness, tmp_path):
    p = tmp_path / "fix.json"
    p.write_text(json.dumps({"rounds": 2, "step": 25, "settings": {}}),
                 encoding="utf-8")
    # Never balances, and every round finds new rows, so only the cap stops it.
    harness["reports"] = [_rep({"A": 5000, "B": 10})]
    harness["counts"] = [{"A": 100, "B": 5}, {"A": 100, "B": 30},
                         {"A": 100, "B": 55}, {"A": 100, "B": 80}]

    run_fix.main([str(p)])

    assert _stages(harness).count("source") == 2


def test_the_loop_stops_when_a_round_finds_no_new_sources(harness, cfg):
    """Discovery is exhausted for this sub-domain: more rounds cannot help, and
    spinning would burn the search budget for nothing."""
    harness["reports"] = [_rep({"A": 5000, "B": 10})]
    harness["counts"] = [{"A": 100, "B": 5}, {"A": 100, "B": 5}]   # unchanged

    run_fix.main([cfg])

    assert _stages(harness).count("source") == 1
    assert _stages(harness)[-1] == "schema"


def test_the_dataset_is_rebuilt_even_when_the_corpus_never_balances(harness, cfg):
    """A fix run that cannot finish the job must still leave a usable dataset."""
    harness["reports"] = [_rep({"A": 5000, "B": 10})]
    harness["counts"] = [{"A": 100, "B": 5}, {"A": 100, "B": 5}]

    run_fix.main([cfg])

    assert _stages(harness)[-1] == "schema"


def test_every_eda_in_the_loop_is_unenforced(harness, cfg):
    """An enforced gate raises SufficiencyError on a blocker, which would end the
    fix run at the first look: the exact situation the fix exists to repair."""
    harness["reports"] = [_rep({"A": 5000, "B": 10}), _rep({"A": 5000, "B": 5000})]
    harness["counts"] = [{"A": 100, "B": 5}, {"A": 100, "B": 60}]

    run_fix.main([cfg])

    for argv in harness["ran"]:
        if argv[0] == "eda":
            assert "--no-enforce" in argv


def test_a_sourcing_failure_does_not_end_the_run(harness, cfg, monkeypatch):
    """SearXNG being down is not a reason to abandon the corpus."""
    harness["reports"] = [_rep({"A": 5000, "B": 10})]
    harness["counts"] = [{"A": 100, "B": 5}, {"A": 100, "B": 5}]

    def _boom(argv):
        harness["ran"].append(list(argv))
        if argv[0] == "source":
            raise RuntimeError("searxng offline")

    monkeypatch.setattr(run_fix, "_run_stage", _boom)
    run_fix.main([cfg])

    assert _stages(harness)[-1] == "schema"


def test_a_clean_failure_is_not_swallowed(harness, cfg, monkeypatch):
    """Sourcing is best-effort; a broken clean is a real failure and must surface."""
    harness["reports"] = [_rep({"A": 5000, "B": 10})]
    harness["counts"] = [{"A": 100, "B": 5}, {"A": 100, "B": 60}]

    def _boom(argv):
        harness["ran"].append(list(argv))
        if argv[0] == "clean":
            raise RuntimeError("disk full")

    monkeypatch.setattr(run_fix, "_run_stage", _boom)
    with pytest.raises(RuntimeError, match="disk full"):
        run_fix.main([cfg])


def test_each_rounds_fill_target_asks_for_more_than_the_domain_already_has(
        harness, tmp_path):
    """A target at or below the domain's current rows is a no-op: the fill sizes
    its deficit as target minus existing, so the round would discover nothing and
    the loop would spin."""
    p = tmp_path / "fix.json"
    p.write_text(json.dumps({"rounds": 2, "step": 25, "settings": {}}),
                 encoding="utf-8")
    harness["reports"] = [_rep({"A": 5000, "B": 10})]
    # Round 1 sees B at 5 (aims at parity with A, 100); round 2 sees B grown past
    # A to 120, where parity would ask for less than B has, so it steps above it.
    harness["counts"] = [{"A": 100, "B": 5}, {"A": 100, "B": 60},
                         {"A": 100, "B": 120}, {"A": 100, "B": 200}]
    seen_before = [{"A": 100, "B": 5}, {"A": 100, "B": 120}]

    run_fix.main([str(p)])

    targets = [int(argv[argv.index("--target-per-domain") + 1])
               for argv in harness["ran"] if argv[0] == "source"]
    assert len(targets) == 2
    for target, before in zip(targets, seen_before, strict=True):
        assert target > before["B"]


def test_a_missing_config_path_is_refused(harness):
    with pytest.raises(SystemExit):
        run_fix.main([])


# ------------------------------------------------------------ launching --------
def test_starting_a_fix_run_spawns_the_loop_with_its_config(tmp_path, monkeypatch):
    from cybersec_slm.dashboard import control

    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    monkeypatch.setattr(control, "_spawn_detached", lambda cmd, root, logs: 4321)
    monkeypatch.setattr(control, "status", lambda: {"running": False, "pid": None})

    out = control.start("eda-fix", settings={"fix_rounds": 3, "workers": 4})

    assert out["ok"] and out["pid"] == 4321
    cfg = json.loads((tmp_path / "logs" / control.FIX_NAME).read_text(encoding="utf-8"))
    assert cfg["rounds"] == 3
    assert cfg["settings"] == {"workers": 4}      # loop knobs are not stage flags


def test_the_fix_config_defaults_the_loop_knobs():
    from cybersec_slm.dashboard import control, rebalance

    cfg = control.build_fix_config({})

    assert cfg["rounds"] == rebalance.DEFAULT_ROUNDS
    assert cfg["step"] == rebalance.DEFAULT_ROW_STEP


def test_a_fix_run_reports_itself_as_resuming(tmp_path, monkeypatch):
    """Its ingest and clean rounds resume, so status must not claim a fresh run."""
    from cybersec_slm.dashboard import control

    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    monkeypatch.setattr(control, "_spawn_detached", lambda cmd, root, logs: 1)
    monkeypatch.setattr(control, "status", lambda: {"running": False, "pid": None})

    assert control.start("eda-fix", settings={})["resume"] is True
