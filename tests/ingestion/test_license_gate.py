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
    # plain-English usage grants captured from a source's terms-of-use prose
    "Free for commercial use",
    "Commercial use permitted",
    "Royalty-free",
    "Free to use",
    # GODL-India: data.gov.in's licence, commercial use permitted with attribution
    "Government Open Data License - India (GODL)",
    "GODL-India",
    "GODL",
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
    # non-commercial usage grant captured from terms-of-use prose
    "Non-commercial use only",
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


# A kill switch decides whether a confirmed-red licence is fetched, so an input it
# does not understand must never be read as "off". These are the values a human
# actually types or a broken .env actually produces.
@pytest.mark.parametrize("value", ["2", "yess", "", "  ", "maybe", "TRUE!",
                                   "off-ish", "1.0", "enabled"])
def test_an_unrecognized_switch_value_still_enforces_the_gate(monkeypatch, value):
    """Fail closed. `_enforced` used to return True only for a fixed allow-list of
    on-words, so every one of these silently disabled the gate for every source."""
    monkeypatch.setenv("CYBERSEC_SLM_ENFORCE_LICENSE_GATE", value)

    ok, reason = license_gate.is_license_ok({"license": "GPL-3.0"})

    assert ok is False, f"{value!r} disabled the licence gate"
    assert "disabled" not in reason.lower()


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "FALSE", " 0 ", "No"])
def test_an_explicit_recognized_off_value_disables_the_gate(monkeypatch, value):
    """Turning it off deliberately still has to work: it is a real dev affordance."""
    monkeypatch.setenv("CYBERSEC_SLM_ENFORCE_LICENSE_GATE", value)

    ok, reason = license_gate.is_license_ok({"license": "GPL-3.0"})

    assert ok is True
    assert "disabled" in reason.lower()


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", "TRUE", " 1 "])
def test_an_explicit_on_value_enforces_the_gate(monkeypatch, value):
    monkeypatch.setenv("CYBERSEC_SLM_ENFORCE_LICENSE_GATE", value)

    ok, _ = license_gate.is_license_ok({"license": "GPL-3.0"})

    assert ok is False


def test_an_unrecognized_switch_value_is_reported_not_swallowed(monkeypatch):
    """A typo that would have disabled the gate must be loud, not silently ignored.

    The package logger does not propagate to root, so caplog never sees it; record
    the warnings off the module's own logger instead.
    """
    said: list[str] = []
    monkeypatch.setenv("CYBERSEC_SLM_ENFORCE_LICENSE_GATE", "yess")
    monkeypatch.setattr(license_gate.logger, "warning", lambda m: said.append(str(m)))

    license_gate.is_license_ok({"license": "MIT"})

    assert any("yess" in m for m in said)


def test_a_recognized_value_says_nothing(monkeypatch):
    """Only a value that would have silently changed behaviour is worth a warning."""
    said: list[str] = []
    monkeypatch.setenv("CYBERSEC_SLM_ENFORCE_LICENSE_GATE", "0")
    monkeypatch.setattr(license_gate.logger, "warning", lambda m: said.append(str(m)))

    license_gate.is_license_ok({"license": "MIT"})

    assert said == []


# ----------------------------------------------------------- 3-state verdict ----
@pytest.mark.parametrize("raw", ["GPL-3.0", "CC BY-NC-SA 4.0", "CC BY-SA 4.0",
                                 "All Rights Reserved", "AGPL-3.0", "proprietary"])
def test_verdict_confirmed_red_is_blocked(raw):
    assert license_gate.license_verdict(raw) == "blocked"


@pytest.mark.parametrize("raw", ["MIT", "Apache-2.0", "CC BY 4.0", "CC0-1.0"])
def test_verdict_permissive_is_ok(raw):
    assert license_gate.license_verdict(raw) == "ok"


@pytest.mark.parametrize("raw", ["", "   ", None, "Unknown", "ATIS",
                                 "arXiv (non-exclusive)", "some-weird-license",
                                 # "public use" is captured faithfully but is too
                                 # ambiguous to auto-clear the commercial gate.
                                 "Public use"])
def test_verdict_blank_or_unrecognized_is_unknown(raw):
    # Crucially, a blank/unknown license is NOT "blocked" - it is never
    # blacklisted on mere absence, only on a positively-recognised red license.
    assert license_gate.license_verdict(raw) == "unknown"

