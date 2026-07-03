"""Tests for the commercial-only license gate.

The strings below are real values pulled from ``sources/Sources.csv`` so the gate
is exercised against the messiness it actually has to survive (SPDX ids, plain
English, named-entity terms, blanks).
"""

from __future__ import annotations

import pytest

from cybersec_slm.ingestion import license_gate

# Licenses that clearly permit unencumbered commercial use -> pass.
_COMMERCIAL_OK = [
    "MIT",
    "MIT-0",
    "Apache-2.0",
    "Apache 2.0",
    "BSD-3-Clause",
    "IETF Revised BSD",
    "CC0-1.0",
    "CC0 1.0 Universal",
    "CC0: Public domain",
    "Public Domain",
    "Public Domain (NIST)",
    "Public Domain (U.S. Government work, 17 U.S.C. 105)",
    "US-Gov-Public-Domain",
    "CDLA-Permissive-2.0",
    "CC BY 4.0",
    "CC BY-4.0",
    "CC by 4.0",
    "MITRE ATT&CK Terms (free w/ attribution)",
    "MITRE CWE Terms of Use (free use with attribution)",
    "arXiv.org perpetual non-exclusive license (CC BY 4.0)",
]

# Licenses that forbid, restrict, or fail to establish commercial use -> block.
_BLOCKED = [
    # copyleft
    "GPL-3.0",
    "GPL v2",
    "GPL v3",
    "LGPL 3.0",
    # share-alike / non-commercial Creative Commons
    "CC BY-SA 4.0",
    "CC BY-NC-SA 4.0",
    # explicitly conditional / proprietary / unresolved
    "Need Permission for commercial",
    "No License",
    "to-verify",
    "Unknown",
    "Contact",
]


@pytest.mark.parametrize("raw", _COMMERCIAL_OK)
def test_commercial_licenses_pass(raw):
    ok, reason = license_gate.classify_license(raw)
    assert ok is True, f"{raw!r} should pass but was blocked: {reason}"


@pytest.mark.parametrize("raw", _BLOCKED)
def test_non_commercial_and_unknown_blocked(raw):
    ok, _reason = license_gate.classify_license(raw)
    assert ok is False, f"{raw!r} should be blocked but passed"


def test_deny_beats_allow_in_compound_string():
    # "CC BY-NC-SA 4.0" contains an allow-substring ("cc by") AND deny tokens
    # (-nc / -sa); deny must win.
    ok, reason = license_gate.classify_license("CC BY-NC-SA 4.0")
    assert ok is False
    assert "nc" in reason.lower() or "sa" in reason.lower() or "commercial" in reason.lower()


def test_empty_and_none_are_missing_license():
    for raw in ("", "   ", None):
        ok, reason = license_gate.classify_license(raw)
        assert ok is False
        assert "missing" in reason.lower()


def test_unrecognized_license_reports_the_raw_value():
    ok, reason = license_gate.classify_license("ATIS")
    assert ok is False
    assert "ATIS" in reason  # raw echoed so a human can see what to fix/add


# --------------------------------------------------------------- descriptor gate
def test_is_license_ok_reads_descriptor_license():
    ok, _ = license_gate.is_license_ok({"license": "MIT"})
    assert ok is True
    blocked, _ = license_gate.is_license_ok({"license": "GPL-3.0"})
    assert blocked is False


def test_kill_switch_disables_the_gate(monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_ENFORCE_LICENSE_GATE", "0")
    ok, reason = license_gate.is_license_ok({"license": "GPL-3.0"})
    assert ok is True
    assert "disabled" in reason.lower()


def test_gate_enforced_by_default(monkeypatch):
    monkeypatch.delenv("CYBERSEC_SLM_ENFORCE_LICENSE_GATE", raising=False)
    ok, _ = license_gate.is_license_ok({"license": "GPL-3.0"})
    assert ok is False
