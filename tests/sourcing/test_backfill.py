"""Tests for the license backfill over an existing catalog (offline)."""

from __future__ import annotations

import csv
import os

from cybersec_slm.sourcing import backfill

_HEADER = ["Name", "Sub-Domain", "Dataset Link", "License"]
_ROWS = [
    ["HasMit", "AppSec", "https://github.com/a/mit", "MIT"],        # already set
    ["BlankGh", "AppSec", "https://github.com/b/apache", ""],       # -> Apache-2.0
    ["BlankNc", "Cloud", "https://kaggle.com/datasets/c/nc", ""],   # -> CC BY-NC (red)
    ["UnknownLic", "Net", "https://example.com/none", "Unknown"],   # -> stays blank
]

# A stub detector keyed by URL - no network.
_DETECT = {
    "https://github.com/b/apache": "Apache-2.0",
    "https://kaggle.com/datasets/c/nc": "CC BY-NC 4.0",
    "https://example.com/none": "",
}


def _write_catalog(path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(_HEADER)
        w.writerows(_ROWS)


def _read(path):
    with open(path, encoding="utf-8") as f:
        return {r["Name"]: r for r in csv.DictReader(f)}


def _stub_detector(monkeypatch):
    monkeypatch.setattr(backfill, "detect_license",
                        lambda url, **k: _DETECT.get(url, ""))


def test_backfill_detects_writes_and_blacklists(tmp_path, monkeypatch):
    _stub_detector(monkeypatch)
    cat = os.path.join(tmp_path, "Sources.csv")
    _write_catalog(cat)

    summary = backfill.backfill_licenses(cat)

    # 3 blank/Unknown rows scanned (HasMit already licensed, skipped).
    assert summary["scanned"] == 3
    assert summary["detected"] == 2                 # apache + nc
    assert summary["still_unknown"] == 1            # example.com/none
    assert summary["blacklisted"] == 1              # the CC BY-NC row moved out

    rows = _read(cat)
    assert rows["BlankGh"]["License"] == "Apache-2.0"
    assert "BlankNc" not in rows                     # blacklisted, removed
    assert rows["UnknownLic"]["License"] == "Unknown"

    bl = os.path.join(tmp_path, "Blacklist.csv")
    assert os.path.exists(bl)
    with open(bl, encoding="utf-8") as f:
        assert any(r["Name"] == "BlankNc" for r in csv.DictReader(f))


def test_backfill_dry_run_mutates_nothing(tmp_path, monkeypatch):
    _stub_detector(monkeypatch)
    cat = os.path.join(tmp_path, "Sources.csv")
    _write_catalog(cat)

    summary = backfill.backfill_licenses(cat, dry_run=True)

    assert summary["detected"] == 2
    assert summary["blacklisted"] == 1              # reported, not applied
    rows = _read(cat)
    assert rows["BlankGh"]["License"] == ""          # not written
    assert "BlankNc" in rows                          # not moved
    assert not os.path.exists(os.path.join(tmp_path, "Blacklist.csv"))


def test_backfill_limit_caps_detection(tmp_path, monkeypatch):
    _stub_detector(monkeypatch)
    cat = os.path.join(tmp_path, "Sources.csv")
    _write_catalog(cat)

    summary = backfill.backfill_licenses(cat, limit=1, then_blacklist=False)

    assert summary["scanned"] == 1                   # only the first blank row


def test_backfill_no_blacklist_keeps_reds(tmp_path, monkeypatch):
    _stub_detector(monkeypatch)
    cat = os.path.join(tmp_path, "Sources.csv")
    _write_catalog(cat)

    summary = backfill.backfill_licenses(cat, then_blacklist=False)

    assert summary["blacklisted"] == 0
    rows = _read(cat)
    assert rows["BlankNc"]["License"] == "CC BY-NC 4.0"   # detected but kept
