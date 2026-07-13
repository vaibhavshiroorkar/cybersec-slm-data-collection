"""Unit tests for the pure dashboard ui helpers (no Streamlit needed)."""

from __future__ import annotations

from cybersec_slm.dashboard import ui


def test_status_pill_is_plain_text_no_emoji():
    assert ui.status_pill("done") == "done"
    assert ui.status_pill("running") == "running"
    assert ui.status_pill("failed") == "failed"
    # no emoji anywhere in the label
    assert all(ord(c) < 128 for c in ui.status_pill("running"))


def test_status_pill_unknown_state_never_raises():
    out = ui.status_pill("nonsense")
    assert isinstance(out, str) and out
