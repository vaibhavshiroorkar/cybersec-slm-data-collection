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


def _rows(ids):
    return [{"id": i, "subdomain": "D", "label": i} for i in ids]


def test_saved_row_range_no_saved_ids_is_full_range():
    rows = _rows(["a", "b", "c", "d"])
    assert ui._saved_row_range([], rows, 4) == (1, 4)


def test_saved_row_range_contiguous_block_reseeds():
    rows = _rows(["a", "b", "c", "d", "e"])
    # saved ids b,c,d are exactly the contiguous block at positions 2..4
    assert ui._saved_row_range(["b", "c", "d"], rows, 5) == (2, 4)


def test_saved_row_range_scattered_ids_fall_back_to_full():
    rows = _rows(["a", "b", "c", "d", "e"])
    # a and d are not contiguous, so do not silently expand into a filled range
    assert ui._saved_row_range(["a", "d"], rows, 5) == (1, 5)


def test_saved_row_range_unknown_ids_fall_back_to_full():
    rows = _rows(["a", "b", "c"])
    assert ui._saved_row_range(["zzz"], rows, 3) == (1, 3)
