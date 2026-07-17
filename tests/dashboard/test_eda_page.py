"""Render tests for the EDA page's Fix balance control.

The button is the deliverable, so these assert on what reaches the screen and on
what clicking it actually launches. Skips unless the `dashboard` extra is there.
"""

import json
import os

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_PAGE = os.path.join(_REPO, "src", "cybersec_slm", "dashboard", "pages", "4_EDA.py")


def _report(subs, topic_cv=0.0):
    total = sum(subs.values())
    return {
        "ts": "2026-07-17T10:00:00", "passed": True, "violations": [],
        "metrics": {"total": total, "subdomains": dict(subs),
                    "num_subdomains": len(subs),
                    "subdomain_distribution": {k: v / total for k, v in subs.items()},
                    "topic_cv": topic_cv, "dup_rate": 0.0,
                    "concentration": {"worst_share": 0.1},
                    "text_quality": {"avg_tokens": 100}},
    }


@pytest.fixture
def page(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    (tmp_path / "logs" / "eda").mkdir(parents=True)

    def _seed(report):
        with open(tmp_path / "logs" / "eda" / "latest.json", "w",
                  encoding="utf-8") as f:
            json.dump(report, f)

    return _seed


def _all_text(at):
    return " ".join([str(m.value) for m in at.markdown]
                    + [str(c.value) for c in at.caption]
                    + [str(w.value) for w in at.warning]
                    + [str(i.value) for i in at.info]
                    + [str(s.value) for s in at.success])


def _run():
    at = AppTest.from_file(_PAGE, default_timeout=30).run()
    assert not at.exception
    return at


def test_a_starved_subdomain_is_named_and_the_fix_is_offered(page):
    page(_report({"Network Security": 5000, "Cloud Security": 10}))

    at = _run()

    assert "Cloud Security" in _all_text(at)
    assert not at.button(key="fix_run").disabled


def test_a_balanced_corpus_says_so_and_blocks_the_fix(page):
    page(_report({"A": 1000, "B": 1000}))

    at = _run()

    assert "balanced" in _all_text(at).lower()
    assert at.button(key="fix_run").disabled


def test_a_skewed_corpus_with_nothing_starved_does_not_offer_to_delete_data(page):
    """Capping is the only lever left here and it deletes cleaned records, so the
    button stays off rather than quietly trimming the corpus."""
    page(_report({"A": 1000, "B": 1000}, topic_cv=9.9))

    at = _run()

    assert at.button(key="fix_run").disabled
    assert "clean balance --cap" in _all_text(at)


def test_the_page_survives_having_no_eda_report_yet(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))

    at = _run()

    assert at.button(key="fix_run").disabled


def test_clicking_fix_launches_a_fix_run_with_the_chosen_rounds(page, monkeypatch):
    page(_report({"Network Security": 5000, "Cloud Security": 10}))
    started = {}

    from cybersec_slm.dashboard import control

    def _fake_start(stage, *, resume=False, settings=None, _command=None):
        started["stage"] = stage
        started["settings"] = settings
        return {"ok": True, "pid": 1}

    monkeypatch.setattr(control, "start", _fake_start)
    monkeypatch.setattr(control, "status", lambda: {"running": False, "pid": None,
                                                    "stale": False})

    at = AppTest.from_file(_PAGE, default_timeout=30).run()
    at.number_input(key="fix_rounds").set_value(2).run()
    at.button(key="fix_run").click().run()

    assert started["stage"] == "eda-fix"
    assert started["settings"]["fix_rounds"] == 2


def test_the_fix_is_blocked_while_another_run_is_active(page, monkeypatch):
    page(_report({"Network Security": 5000, "Cloud Security": 10}))

    from cybersec_slm.dashboard import control

    monkeypatch.setattr(control, "status", lambda: {"running": True, "pid": 9,
                                                    "stale": False})

    at = _run()

    assert at.button(key="fix_run").disabled
