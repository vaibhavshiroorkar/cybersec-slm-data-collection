"""What the catalog cost: every discovery run added up.

The per-run funnel says where one run's hits went. It cannot answer what an
operator actually asks -- "how much did I look through to get these 1,020
sources" -- because they were not found in one run and the newest summary knows
nothing of the ones before it.
"""

import json

from cybersec_slm.core import DEFAULT_PROFILE as PROFILE
from cybersec_slm.dashboard import data


def _summary(root, day, *, found=0, appended=0, new=0, funnel=True,
             dropped=None, dups=0, candidates=0, elapsed=10.0):
    d = root / "logs" / PROFILE / "discovered"
    d.mkdir(parents=True, exist_ok=True)
    body = {"found": found, "new": new, "appended": appended, "elapsed_s": elapsed}
    if funnel:
        dropped = dropped if dropped is not None else {"junk host": 0}
        body["funnel"] = {
            "found": found, "dropped": dropped,
            "dropped_total": sum(dropped.values()), "duplicates": dups,
            "candidates": candidates, "unprocessed": 0,
            "license": {"ok": appended, "unknown": 0, "blocked": 0},
            "appended": appended,
        }
    (d / f"summary-{day}.json").write_text(json.dumps(body), encoding="utf-8")


def test_no_runs_reports_nothing_rather_than_zeroes_that_look_real(tmp_path,
                                                                   monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))

    out = data.sourcing_totals()

    assert out["runs"] == 0
    assert out["found"] == 0
    assert out["ratio"] == 0.0


def test_every_run_is_added_up_not_just_the_newest(tmp_path, monkeypatch):
    """The bug this exists for: latest_source_summary() reads one file, so the
    page could only ever describe the last run."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _summary(tmp_path, "20260715", found=10_000, appended=400, dups=300,
             candidates=600)
    _summary(tmp_path, "20260716", found=31_000, appended=620, dups=900,
             candidates=1_400)

    out = data.sourcing_totals()

    assert out["runs"] == 2
    assert out["found"] == 41_000
    assert out["appended"] == 1_020
    assert out["duplicates"] == 1_200


def test_the_headline_is_hits_looked_at_per_source_kept(tmp_path, monkeypatch):
    """41,000 searched for 1,020 kept says whether the keywords are aimed well;
    no single run's numbers do."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _summary(tmp_path, "20260715", found=10_200, appended=1_020)

    assert data.sourcing_totals()["ratio"] == 10.0


def test_the_ratio_is_not_a_division_by_zero(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _summary(tmp_path, "20260715", found=500, appended=0)

    assert data.sourcing_totals()["ratio"] == 0.0


def test_a_pre_funnel_run_still_counts_its_sources_but_not_its_hits(tmp_path,
                                                                    monkeypatch):
    """Some summaries predate the funnel. They really did add sources, so they
    count; their hits are unknown, and with_funnel makes that visible rather than
    burying it in a total that looks complete."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _summary(tmp_path, "20260714", appended=200, funnel=False)
    _summary(tmp_path, "20260715", found=10_000, appended=400)

    out = data.sourcing_totals()

    assert out["runs"] == 2
    assert out["with_funnel"] == 1
    assert out["appended"] == 600      # both runs' sources
    assert out["found"] == 10_000      # only the run that recorded its hits


def test_drop_reasons_are_added_up_across_runs(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _summary(tmp_path, "20260715", found=100, appended=1,
             dropped={"junk host": 30, "listing page": 5})
    _summary(tmp_path, "20260716", found=100, appended=1,
             dropped={"junk host": 10, "restricted host": 50})

    out = data.sourcing_totals()

    assert out["dropped"] == 95
    assert out["dropped_by"]["junk host"] == 40
    # Worst first: the reason to act on is the one costing the most hits.
    assert list(out["dropped_by"])[0] == "restricted host"


def test_licence_verdicts_are_added_up(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _summary(tmp_path, "20260715", found=100, appended=7)
    _summary(tmp_path, "20260716", found=100, appended=3)

    assert data.sourcing_totals()["license"]["ok"] == 10


def test_a_malformed_summary_does_not_break_the_total(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _summary(tmp_path, "20260715", found=100, appended=10)
    (tmp_path / "logs" / PROFILE / "discovered" / "summary-bad.json").write_text(
        "{not json", encoding="utf-8")

    out = data.sourcing_totals()

    assert out["found"] == 100
    assert out["appended"] == 10


def test_totals_are_per_profile(tmp_path, monkeypatch):
    """Logs are per-profile now, so one corpus's discovery cost is not the other's."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _summary(tmp_path, "20260715", found=999, appended=9)

    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "cybersec")
    assert data.sourcing_totals()["runs"] == 0     # a different profile's logs
