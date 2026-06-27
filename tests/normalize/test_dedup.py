"""Tests for near-duplicate detection + failure tracking."""

from __future__ import annotations

import json

from cybersec_slm.normalize.dedup import (
    FailureTracker,
    NearDuplicateIndex,
    categorize_failure,
)

_A = ("Cross-site scripting allows an attacker to inject malicious script into a "
      "trusted web page that is then viewed by other unsuspecting users online.")


def test_exact_and_unique():
    idx = NearDuplicateIndex()
    is_dup, reason, score = idx.is_duplicate(_A)
    assert not is_dup and reason == "" and score == 0.0
    idx.add(_A, "k1")
    is_dup, reason, score = idx.is_duplicate(_A)
    assert is_dup and reason == "exact" and score == 1.0


def test_near_duplicate_scored():
    idx = NearDuplicateIndex()
    idx.add(_A, "k1")
    near = _A.replace("unsuspecting users online", "unsuspecting site visitors today")
    is_dup, reason, score = idx.is_duplicate(near)
    assert is_dup and reason == "near"
    assert 0.5 < score < 1.0


def test_rebuild_from_jsonl(tmp_path):
    p = tmp_path / "dataset.jsonl"
    p.write_text(json.dumps({"id": "x", "text": _A, "content_hash": "n/a"}) + "\n",
                 encoding="utf-8")
    idx = NearDuplicateIndex()
    assert idx.rebuild_from_jsonl(p) == 1
    is_dup, reason, _ = idx.is_duplicate(_A)
    assert is_dup and reason == "exact"


def test_categorize_failure():
    assert categorize_failure("domain not in allowlist: 'X'") == "DIRTY_DATA"
    assert categorize_failure("text shorter than 20 chars") == "DIRTY_DATA"
    assert categorize_failure("no usable text") == "MAPPER_MISMATCH"
    assert categorize_failure("something odd") == "AMBIGUOUS"


def test_failure_tracker_escalate_and_pause():
    ft = FailureTracker(escalate=3, threshold=5)
    for _ in range(2):
        ft.classify_failure("src", "text shorter than 20 chars")
    assert ft.should_pause("src") is False
    ft.classify_failure("src", "text shorter than 20 chars")   # hits escalate (3)
    assert ft.categories["DIRTY_DATA"] == 3
    for _ in range(2):
        ft.classify_failure("src", "text shorter than 20 chars")   # now 5 -> pause
    assert ft.should_pause("src") is True
    assert ft.should_pause("src") is False        # only flips once
    assert "src" in ft.paused_sources()
