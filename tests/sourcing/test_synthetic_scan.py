"""Tests for the keyword-based synthetic-source suggester (curation aid)."""

from __future__ import annotations

import pandas as pd

from cybersec_slm.ingestion import sources
from cybersec_slm.sourcing import synthetic_scan as ss


def test_classify_strong_weak_none():
    s, conf, matched = ss.classify_text("Synthetic SIEM security-event logs")
    assert s == "Yes" and conf == "high" and "synthetic" in matched

    s, conf, matched = ss.classify_text("GDPR question-answer instruction set")
    assert s == "review" and conf == "low" and matched            # weak only

    s, conf, matched = ss.classify_text("NIST SP 800-53 Security & Privacy Controls")
    assert s == "No" and matched == []


def test_dpo_and_generation_word_boundaries():
    # 'dpo' as a standalone token -> strong; not matched inside another word
    assert ss.classify_text("secure/insecure code pairs (DPO)")[0] == "Yes"
    assert ss.classify_text("firewall endpoint traffic logs")[0] == "No"
    # 'generation' must not trigger the 'generated' weak term
    assert ss.classify_text("text-to-circuit generation pairs")[0] == "No"


def _catalog(tmp_path, rows):
    df = pd.DataFrame([{c: r.get(c, "") for c in sources.CATALOG_COLUMNS} for r in rows])
    p = tmp_path / "cat.csv"
    df.to_csv(p, index=False, encoding="utf-8")
    return str(p)


def test_scan_flags_gaps_and_disagreements(tmp_path):
    cat = _catalog(tmp_path, [
        # strong term, not flagged -> GAP
        {"Name": "syn", "Description": "Synthetic firewall logs",
         "Dataset Link": "https://hf/x/syn", "Is Synthetic?": ""},
        # flagged by hand, no keyword -> DISAGREEMENT
        {"Name": "pii", "Description": "PII detection / masking dataset",
         "Dataset Link": "https://hf/x/pii", "Is Synthetic?": "Yes"},
        # clean real doc -> No, not flagged -> neither
        {"Name": "nist", "Description": "NIST risk management framework",
         "Dataset Link": "https://nist/x", "Is Synthetic?": ""},
    ])
    rows = {r["name"]: r for r in ss.scan(cat)}
    assert rows["syn"]["suggested"] == "Yes" and rows["syn"]["gap"] is True
    assert rows["pii"]["disagreement"] is True and rows["pii"]["suggested"] == "No"
    assert rows["nist"]["gap"] is False and rows["nist"]["disagreement"] is False


def test_apply_writes_only_high_confidence_gaps(tmp_path):
    cat = _catalog(tmp_path, [
        {"Name": "syn", "Description": "Synthetic logs",
         "Dataset Link": "https://hf/x/syn", "Is Synthetic?": ""},
        {"Name": "qa", "Description": "question-answer instruction pairs",  # weak -> review
         "Dataset Link": "https://hf/x/qa", "Is Synthetic?": ""},
    ])
    rows = ss.scan(cat)
    changed = ss.apply_suggestions(cat, rows)
    assert changed == ["syn"]                              # only the strong-term gap

    df = pd.read_csv(cat, dtype=str, keep_default_na=False)
    flags = dict(zip(df["Name"], df["Is Synthetic?"], strict=False))
    assert flags["syn"] == "Yes" and flags["qa"] == ""     # review row untouched

    # idempotent: re-applying changes nothing new
    assert ss.apply_suggestions(cat, ss.scan(cat)) == []
