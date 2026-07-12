"""Unit tests for the pure dashboard ui helpers (no Streamlit needed)."""

from __future__ import annotations

from cybersec_slm.dashboard import ui


def test_status_pill_has_emoji_per_state():
    assert "✅" in ui.status_pill("done")
    assert "🟢" in ui.status_pill("running")
    assert "⛔" in ui.status_pill("failed")


def test_status_pill_unknown_state_never_raises():
    out = ui.status_pill("nonsense")
    assert isinstance(out, str) and out
