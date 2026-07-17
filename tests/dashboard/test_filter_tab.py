"""The Sourcing page's Filter tab: judge the catalog by a rule, then apply it.

The feature already existed as `source review --condition "..."`; it was only ever
reachable from the CLI, so nobody saw it. These tests are about the UI contract,
above all that nothing moves until it is applied.
"""

import os

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

from cybersec_slm.core import DEFAULT_PROFILE as PROFILE  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_PAGE = os.path.join(_REPO, "src", "cybersec_slm", "dashboard", "pages",
                     "1_Sourcing.py")


@pytest.fixture
def page(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    from cybersec_slm.sourcing import profiles

    d = profiles.profile_dir(PROFILE)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "Sources.csv"), "w", encoding="utf-8") as f:
        f.write("Name,Sub-Domain,Description,Dataset Link,Category,License\n"
                "rbi-circulars,AML-KYC,RBI master direction on KYC,"
                "https://rbi.org.in/x,Document,Public Domain\n"
                "us-only-corpus,AML-KYC,A United States AML corpus,"
                "https://example.test/us,Dataset,MIT\n")
    return tmp_path


def _run():
    at = AppTest.from_file(_PAGE, default_timeout=60).run()
    assert not at.exception
    return at


def test_the_filter_tab_renders_and_asks_for_a_condition(page):
    at = _run()

    assert at.text_input(key="rev_condition") is not None
    # Nothing to judge against yet, so judging is off rather than judging "".
    assert at.button(key="rev_scan").disabled


def test_judging_is_offered_once_a_condition_is_typed(page):
    at = AppTest.from_file(_PAGE, default_timeout=60).run()

    at.text_input(key="rev_condition").set_value("the data must concern India").run()

    assert not at.button(key="rev_scan").disabled


def test_a_missing_model_is_named_rather_than_failing_at_the_click(page,
                                                                   monkeypatch):
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)

    at = _run()

    text = " ".join(str(w.value) for w in at.warning)
    assert "NVIDIA_API_KEY" in text


def test_judging_shows_every_verdict_and_moves_nothing(page, monkeypatch):
    """The safety property: a judged catalog is a report, not an edit."""
    from cybersec_slm.sourcing import review

    def _fake(condition, spec=None, *, apply=False, cli=None):
        return {
            "report": "logs/reviews/review-x.csv",
            "counts": {review.APPROVE: 1, review.DECLINE: 1, review.REVIEW: 0},
            "results": [
                {"condition": condition, "name": "rbi-circulars",
                 "sub_domain": "AML-KYC", "link": "https://rbi.org.in/x",
                 "category": "Document", "verdict": review.APPROVE,
                 "confidence": "0.95", "reason": "an RBI circular, India"},
                {"condition": condition, "name": "us-only-corpus",
                 "sub_domain": "AML-KYC", "link": "https://example.test/us",
                 "category": "Dataset", "verdict": review.DECLINE,
                 "confidence": "0.91", "reason": "a United States corpus"},
            ],
        }

    monkeypatch.setattr(review, "run_scan", _fake)
    moved = []
    monkeypatch.setattr(review, "apply_report",
                        lambda *a, **k: moved.append(1) or {"moved": 1})

    at = AppTest.from_file(_PAGE, default_timeout=60).run()
    at.text_input(key="rev_condition").set_value("must concern India").run()
    at.button(key="rev_scan").click().run()

    assert not at.exception
    rendered = " ".join(str(df.value) for df in at.dataframe)
    assert "rbi-circulars" in rendered and "us-only-corpus" in rendered
    assert "a United States corpus" in rendered
    assert moved == []                 # judging alone must not move anything
    # The catalog is untouched on disk.
    from cybersec_slm.sourcing import profiles
    body = open(os.path.join(profiles.profile_dir(PROFILE), "Sources.csv"),
                encoding="utf-8").read()
    assert "us-only-corpus" in body


def test_applying_moves_the_declined_rows_and_says_how_many(page, monkeypatch):
    from cybersec_slm.sourcing import review

    monkeypatch.setattr(review, "run_scan", lambda condition, spec=None, **k: {
        "report": "r.csv",
        "counts": {review.APPROVE: 0, review.DECLINE: 1, review.REVIEW: 0},
        "results": [{"condition": condition, "name": "us-only-corpus",
                     "sub_domain": "AML-KYC", "link": "https://example.test/us",
                     "category": "Dataset", "verdict": review.DECLINE,
                     "confidence": "0.9", "reason": "not India"}],
    })
    seen = {}

    def _apply(path, *, spec=None, condition=None):
        seen["path"], seen["condition"] = path, condition
        return {"moved": 1}

    monkeypatch.setattr(review, "apply_report", _apply)

    at = AppTest.from_file(_PAGE, default_timeout=60).run()
    at.text_input(key="rev_condition").set_value("must concern India").run()
    at.button(key="rev_scan").click().run()
    at.button(key="rev_apply").click().run()

    assert not at.exception
    assert seen["path"] == "r.csv"
    # The condition travels with the apply: applying a report built for a
    # different question would remove sources for a reason nobody asked about.
    assert seen["condition"] == "must concern India"


def test_apply_is_off_when_nothing_was_declined(page, monkeypatch):
    from cybersec_slm.sourcing import review

    monkeypatch.setattr(review, "run_scan", lambda condition, spec=None, **k: {
        "report": "r.csv",
        "counts": {review.APPROVE: 2, review.DECLINE: 0, review.REVIEW: 0},
        "results": [{"condition": condition, "name": "a", "sub_domain": "x",
                     "link": "l", "category": "c", "verdict": review.APPROVE,
                     "confidence": "0.9", "reason": "fine"}],
    })

    at = AppTest.from_file(_PAGE, default_timeout=60).run()
    at.text_input(key="rev_condition").set_value("must concern India").run()
    at.button(key="rev_scan").click().run()

    assert at.button(key="rev_apply").disabled


def test_a_failed_review_is_reported_not_raised(page, monkeypatch):
    from cybersec_slm.sourcing import review

    def _boom(condition, spec=None, **k):
        raise RuntimeError("NIM unreachable")

    monkeypatch.setattr(review, "run_scan", _boom)

    at = AppTest.from_file(_PAGE, default_timeout=60).run()
    at.text_input(key="rev_condition").set_value("must concern India").run()
    at.button(key="rev_scan").click().run()

    assert not at.exception
    assert any("NIM unreachable" in str(e.value) for e in at.error)
