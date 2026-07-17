"""The Test run: a pipeline health check that cannot touch the corpus.

The isolation is the whole feature. A smoke test people are afraid to press is a
smoke test nobody presses, so the tests that matter here are the ones proving the
real data root is not reachable from the run.
"""

import json
import os

from cybersec_slm.dashboard import control, run_test


# ------------------------------------------------------------- isolation ------
def test_starting_a_test_run_points_the_child_at_a_scratch_root(tmp_path,
                                                                monkeypatch):
    """The safety property: the child's data root is a temp dir, not the corpus."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    seen = {}

    def _spawn(cmd, root, logs):
        seen["cmd"], seen["root"] = cmd, root
        return 999

    monkeypatch.setattr(control, "_spawn_detached", _spawn)
    monkeypatch.setattr(control, "status", lambda: {"running": False, "pid": None})

    out = control.start("test-run")

    assert out["ok"]
    assert seen["root"] != str(tmp_path)
    assert "testrun" in seen["root"]
    assert "run_test" in " ".join(seen["cmd"])


def test_the_scratch_root_carries_the_profiles_sources(tmp_path, monkeypatch):
    """Without the catalog the run would silently test the built-in defaults
    instead of this profile."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    src = tmp_path / "sources" / "profiles" / "cybersec"
    src.mkdir(parents=True)
    (src / "Sources.csv").write_text("Name,Sub-Domain\nx,Network Security\n",
                                     encoding="utf-8")

    scratch = control._make_scratch_root()

    copied = os.path.join(scratch, "sources", "profiles", "cybersec", "Sources.csv")
    assert os.path.exists(copied)


def test_a_missing_sources_tree_does_not_stop_the_scratch_root(tmp_path,
                                                               monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))

    assert os.path.isdir(control._make_scratch_root())


def test_the_report_lands_under_the_real_root_not_the_scratch(tmp_path,
                                                              monkeypatch):
    """The one intentional write outside the scratch: a small JSON the page reads.
    It has to be the real root, or the result would vanish with the temp dir."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    monkeypatch.setattr(control, "_spawn_detached", lambda cmd, root, logs: 1)
    monkeypatch.setattr(control, "status", lambda: {"running": False, "pid": None})

    control.start("test-run")

    cfg = json.loads((tmp_path / "logs" / control.TEST_CFG_NAME)
                     .read_text(encoding="utf-8"))
    assert cfg["report"] == str(tmp_path / "logs" / control.TEST_REPORT_NAME)


def test_a_test_run_does_not_claim_to_be_resuming(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    monkeypatch.setattr(control, "_spawn_detached", lambda cmd, root, logs: 1)
    monkeypatch.setattr(control, "status", lambda: {"running": False, "pid": None})

    assert control.start("test-run")["resume"] is False


# ---------------------------------------------------------------- the run -----
def test_seeding_writes_a_raw_corpus_the_cleaner_can_read(tmp_path):
    n = run_test._seed(str(tmp_path), "Network Security")

    p = tmp_path / "data" / "raw" / "Network Security" / "testrun" / "data.jsonl"
    recs = [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines()]
    assert n == len(recs) == run_test.SEED_RECORDS
    for r in recs:
        # sanitize.REQUIRED_FIELDS: without these the cleaner drops every record
        # and the run would "pass" having proved nothing.
        assert {"source", "url", "license", "text"} <= set(r)
        assert len(r["text"]) > 50


def test_a_failing_step_is_reported_rather_than_crashing_the_run():
    """A Test run must always produce a report, most of all when it fails."""
    def _boom():
        raise RuntimeError("stage exploded")

    out = run_test._step("clean", _boom)

    assert out["ok"] is False
    assert "stage exploded" in out["detail"]
    assert out["step"] == "clean"


def test_a_passing_step_is_timed():
    out = run_test._step("clean", lambda: None)

    assert out["ok"] is True
    assert out["seconds"] >= 0


def test_the_seed_subdomain_comes_from_the_live_taxonomy():
    """Hardcoding one would fail the moment the profile changed, and a health
    check that fails because of the health check is worse than none."""
    from cybersec_slm.sourcing import catalog

    assert run_test._first_subdomain() in list(catalog.subdomains(catalog.load()))


def test_a_missing_config_path_is_refused():
    import pytest

    with pytest.raises(SystemExit):
        run_test.main([])
