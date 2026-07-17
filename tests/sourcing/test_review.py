"""Model-judged catalog review: verdict parsing, propose/apply, Excluded.csv.

Every test drives a FAKE client — never a real NIM call.
"""

import csv
import os

import pytest

from cybersec_slm import llm
from cybersec_slm.core import DEFAULT_PROFILE as PROFILE
from cybersec_slm.sourcing import review

_COLS = ["Name", "Sub-Domain", "Description", "Dataset Link", "Category",
         "License"]


class _FakeClient:
    """Stands in for the NIM client, replying with a queued script."""

    def __init__(self, replies):
        self._replies = list(replies)
        self.prompts: list[str] = []
        self.chat = self                      # cli.chat.completions.create(...)
        self.completions = self

    def create(self, *, model, temperature, messages):
        self.prompts.append(messages[-1]["content"])
        reply = self._replies.pop(0)
        if isinstance(reply, Exception):
            raise reply

        class _M:
            content = reply

        class _C:
            message = _M()

        class _R:
            choices = [_C()]

        return _R()


def _catalog(tmp_path, rows):
    path = tmp_path / "Sources.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=_COLS)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return str(path)


def _row(name, link, desc=""):
    return {"Name": name, "Sub-Domain": "AML-KYC", "Description": desc,
            "Dataset Link": link, "Category": "Dataset", "License": "MIT"}


def _redirect(monkeypatch, tmp_path):
    """Point the reports and Excluded.csv at tmp (never the real repo)."""
    monkeypatch.setattr(review, "reviews_dir",
                        lambda: str(tmp_path / "logs" / PROFILE / "reviews"))
    monkeypatch.setattr(review, "excluded_path",
                        lambda profile=None: str(tmp_path / "Excluded.csv"))


# ------------------------------------------------------------------ parsing ---
@pytest.mark.parametrize("reply,expected", [
    ('{"verdict":"approve","confidence":0.9,"reason":"about India"}', "approve"),
    ('```json\n{"verdict":"decline","confidence":0.9,"reason":"US only"}\n```',
     "decline"),                                        # fenced JSON
    ('Sure! {"verdict":"decline","confidence":0.8,"reason":"US only"} hope this helps',
     "decline"),                                        # prose around the JSON
    ("not json at all", "review"),                      # unparseable -> review
    ('{"verdict":"maybe","confidence":0.9,"reason":"x"}', "review"),  # bad verdict
    ("", "review"),                                     # empty reply
])
def test_parse_reply_verdicts(reply, expected):
    assert review._parse(reply)[0] == expected


def test_low_confidence_decline_is_downgraded_to_review():
    """A hesitant decline must not remove a source; it goes to a human."""
    cli = _FakeClient(['{"verdict":"decline","confidence":0.3,"reason":"unsure"}'])
    verdict, conf, reason = review.classify_row(_row("A", "http://a"), "about India",
                                                cli=cli)
    assert verdict == "review" and conf == 0.3
    assert "low-confidence" in reason


def test_per_row_error_becomes_review_not_a_crash():
    """One failed row must not end a scan over a whole catalog."""
    cli = _FakeClient([TimeoutError("nim timed out")])
    verdict, _conf, reason = review.classify_row(_row("A", "http://a"), "cond",
                                                 cli=cli)
    assert verdict == "review" and "TimeoutError" in reason


def test_prompt_carries_the_condition_and_metadata():
    cli = _FakeClient(['{"verdict":"approve","confidence":1,"reason":"ok"}'])
    review.classify_row(_row("RBI circulars", "http://a", "Indian banking rules"),
                        "the data must concern India", cli=cli)
    prompt = cli.prompts[0]
    assert "the data must concern India" in prompt
    assert "RBI circulars" in prompt and "Indian banking rules" in prompt


# ------------------------------------------------------------ propose / apply --
def test_run_scan_is_propose_only_and_writes_a_report(tmp_path, monkeypatch):
    """A review pass judges and records, but never touches the catalog."""
    _redirect(monkeypatch, tmp_path)
    spec = _catalog(tmp_path, [_row("Keep", "http://keep"),
                               _row("Drop", "http://drop")])
    cli = _FakeClient(['{"verdict":"approve","confidence":0.9,"reason":"in scope"}',
                       '{"verdict":"decline","confidence":0.9,"reason":"US only"}'])

    out = review.run_scan("about India", spec, cli=cli)

    assert out["counts"] == {"approve": 1, "decline": 1, "review": 0}
    assert os.path.exists(out["report"])
    # catalog untouched: propose-only
    with open(spec, encoding="utf-8") as f:
        assert "http://drop" in f.read()
    assert not os.path.exists(str(tmp_path / "Excluded.csv"))


def test_apply_moves_declined_rows_to_excluded_with_the_reason(tmp_path, monkeypatch):
    _redirect(monkeypatch, tmp_path)
    spec = _catalog(tmp_path, [_row("Keep", "http://keep"),
                               _row("Drop", "http://drop")])
    cli = _FakeClient(['{"verdict":"approve","confidence":0.9,"reason":"in scope"}',
                       '{"verdict":"decline","confidence":0.9,"reason":"US only"}'])

    out = review.run_scan("about India", spec, apply=True, cli=cli)
    assert out["applied"]["moved"] == 1

    with open(spec, encoding="utf-8") as f:
        body = f.read()
    assert "http://keep" in body and "http://drop" not in body   # removed

    with open(str(tmp_path / "Excluded.csv"), encoding="utf-8", newline="") as f:
        excluded = list(csv.DictReader(f))
    assert len(excluded) == 1
    assert excluded[0]["Dataset Link"] == "http://drop"
    assert excluded[0][review.EXCLUDED_REASON_COL] == "US only"   # reason survives


def test_apply_leaves_review_verdicts_alone(tmp_path, monkeypatch):
    """`review` is a human's call, never applied."""
    _redirect(monkeypatch, tmp_path)
    spec = _catalog(tmp_path, [_row("Unsure", "http://unsure")])
    cli = _FakeClient(["not json at all"])                       # -> review

    out = review.run_scan("about India", spec, apply=True, cli=cli)
    assert out["counts"]["review"] == 1
    assert out["applied"]["moved"] == 0
    with open(spec, encoding="utf-8") as f:
        assert "http://unsure" in f.read()


def test_apply_is_idempotent(tmp_path, monkeypatch):
    """Replaying a report finds its rows already gone and does nothing."""
    _redirect(monkeypatch, tmp_path)
    spec = _catalog(tmp_path, [_row("Drop", "http://drop")])
    cli = _FakeClient(['{"verdict":"decline","confidence":0.9,"reason":"US only"}'])

    out = review.run_scan("about India", spec, apply=True, cli=cli)
    assert out["applied"]["moved"] == 1
    again = review.apply_report(out["report"], spec=spec)
    assert again["moved"] == 0

    with open(str(tmp_path / "Excluded.csv"), encoding="utf-8", newline="") as f:
        assert len(list(csv.DictReader(f))) == 1        # not duplicated


def test_apply_refuses_a_report_for_a_different_condition(tmp_path, monkeypatch):
    """Applying a report built for another question would remove sources for a
    reason you never asked about."""
    _redirect(monkeypatch, tmp_path)
    spec = _catalog(tmp_path, [_row("Drop", "http://drop")])
    cli = _FakeClient(['{"verdict":"decline","confidence":0.9,"reason":"US only"}'])
    out = review.run_scan("about India", spec, cli=cli)

    with pytest.raises(ValueError, match="was generated for"):
        review.apply_report(out["report"], spec=spec, condition="about Brazil")

    with open(spec, encoding="utf-8") as f:
        assert "http://drop" in f.read()                # untouched


# ------------------------------------------------------------------- guards ---
def test_scan_fails_loudly_when_the_model_is_unavailable(tmp_path, monkeypatch):
    """No key / no SDK must error before judging, never degrade to something weaker."""
    _redirect(monkeypatch, tmp_path)
    spec = _catalog(tmp_path, [_row("A", "http://a")])
    monkeypatch.delenv(llm.API_KEY_VAR, raising=False)

    with pytest.raises(llm.LLMUnavailable):
        review.scan("about India", spec)

    with open(spec, encoding="utf-8") as f:
        assert "http://a" in f.read()                   # nothing touched


def test_empty_condition_is_rejected(tmp_path, monkeypatch):
    _redirect(monkeypatch, tmp_path)
    spec = _catalog(tmp_path, [_row("A", "http://a")])
    with pytest.raises(ValueError, match="condition"):
        review.run_scan("   ", spec, cli=_FakeClient([]))
