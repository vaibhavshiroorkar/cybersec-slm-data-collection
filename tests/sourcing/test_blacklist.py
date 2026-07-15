"""Tests for moving confirmed-red sources out of the catalog to a blacklist."""

from __future__ import annotations

import csv
import os

from cybersec_slm.sourcing import blacklist

_HEADER = ["Name", "Sub-Domain", "Dataset Link", "License"]
_ROWS = [
    ["OkMit", "AppSec", "https://github.com/a/mit", "MIT"],
    ["Copyleft", "AppSec", "https://github.com/b/gpl", "GPL-3.0"],
    ["NonComm", "Cloud", "https://huggingface.co/datasets/c/nc", "CC BY-NC 4.0"],
    ["Blank", "Cloud", "https://example.com/blank", ""],
    ["UnknownLic", "Net", "https://example.com/unknown", "Unknown"],
]


def _write_catalog(path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(_HEADER)
        w.writerows(_ROWS)


def _read(path):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_move_flagged_relocates_only_confirmed_red(tmp_path):
    cat = os.path.join(tmp_path, "Sources.csv")
    _write_catalog(cat)

    result = blacklist.move_flagged(cat)

    assert result["moved"] == 2                     # GPL + CC BY-NC only
    remaining = {r["Name"] for r in _read(cat)}
    assert remaining == {"OkMit", "Blank", "UnknownLic"}   # blank/unknown kept

    bl = _read(os.path.join(tmp_path, "Blacklist.csv"))
    moved_names = {r["Name"] for r in bl}
    assert moved_names == {"Copyleft", "NonComm"}
    assert all(r["Blacklist Reason"] for r in bl)   # every move carries a reason


def test_move_flagged_dry_run_writes_nothing(tmp_path):
    cat = os.path.join(tmp_path, "Sources.csv")
    _write_catalog(cat)

    result = blacklist.move_flagged(cat, dry_run=True)

    assert result["moved"] == 2
    assert len(_read(cat)) == len(_ROWS)            # catalog untouched
    assert not os.path.exists(os.path.join(tmp_path, "Blacklist.csv"))


def test_move_flagged_is_idempotent(tmp_path):
    cat = os.path.join(tmp_path, "Sources.csv")
    _write_catalog(cat)

    blacklist.move_flagged(cat)
    second = blacklist.move_flagged(cat)            # nothing red left

    assert second["moved"] == 0


def test_move_flagged_missing_catalog(tmp_path):
    result = blacklist.move_flagged(os.path.join(tmp_path, "nope.csv"))
    assert result == {"moved": 0, "rows": []}
