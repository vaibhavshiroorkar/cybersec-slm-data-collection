"""The security probes: each control proved by making it refuse something.

The point of a probe over a checklist is that it goes red when the control
breaks, so the most important tests here are the ones that break a control and
assert the probe notices.
"""

import json
import os

from cybersec_slm.dashboard import security


def _named(probes, name):
    [p] = [x for x in probes if x.name.lower().startswith(name.lower())]
    return p


# ---------------------------------------------------------------- healthy -----
def test_every_control_passes_on_the_real_code(tmp_path):
    """The suite's own bill of health: every probe green except canaries, which
    are opt-in and not planted here."""
    probes = security.run_probes(dataset=str(tmp_path / "none.jsonl"),
                                 sidecar=str(tmp_path / "none.json"))

    failed = [p for p in probes if not p.passed and p.name != "Canary tokens"]
    assert failed == [], [f"{p.name}: {p.detail}" for p in failed]


def test_a_probe_says_what_it_proved_not_just_that_it_ran(tmp_path):
    probes = security.run_probes(dataset=str(tmp_path / "x"),
                                 sidecar=str(tmp_path / "y"))

    for p in probes:
        assert p.detail and len(p.detail) > 10


def test_the_url_screen_probe_is_tied_to_its_finding(tmp_path):
    probes = security.run_probes(dataset=str(tmp_path / "x"),
                                 sidecar=str(tmp_path / "y"))

    assert _named(probes, "URL screen").finding == "F4"


# ------------------------------------------- a broken control goes red --------
def test_the_url_screen_probe_fails_when_the_screen_is_gutted(monkeypatch):
    """The regression this exists for: someone makes screen() return "" and every
    checklist in the world still says the control is present."""
    from cybersec_slm.ingestion import urlscreen

    monkeypatch.setattr(urlscreen, "screen", lambda url: "")

    probe = security._probe_url_screen()

    assert not probe.passed
    assert "ALLOWED" in probe.detail


def test_the_licence_gate_probe_fails_when_the_gate_is_off(monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_ENFORCE_LICENSE_GATE", "0")

    probe = security._probe_license_gate()

    assert not probe.passed


def test_the_licence_gate_probe_catches_a_fail_open_switch(monkeypatch):
    """Exactly the bug that was live: a typo disabling the gate silently."""
    from cybersec_slm.ingestion import license_gate

    monkeypatch.setattr(license_gate, "_enforced",
                        lambda: os.environ.get(
                            "CYBERSEC_SLM_ENFORCE_LICENSE_GATE", "1"
                        ).lower() in ("1", "true", "yes", "on"))

    probe = security._probe_license_gate()

    assert not probe.passed
    assert "malformed" in probe.detail


def test_the_zip_bomb_probe_fails_when_the_guard_is_removed(monkeypatch):
    from cybersec_slm.ingestion import archive

    monkeypatch.setattr(archive, "safe_extract", lambda *a, **k: [])

    probe = security._probe_zip_bomb()

    assert not probe.passed


def test_the_binary_scan_probe_fails_when_detection_is_removed(monkeypatch):
    from cybersec_slm.ingestion import binscan

    monkeypatch.setattr(binscan, "scan_tree", lambda *a, **k: [])

    probe = security._probe_binary_scan()

    assert not probe.passed


def test_a_probe_that_raises_is_a_red_row_not_a_crash(monkeypatch, tmp_path):
    """The page renders every render; one broken probe must not take it down."""
    from cybersec_slm.ingestion import urlscreen

    def _boom(url):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(urlscreen, "screen", _boom)

    probes = security.run_probes(dataset=str(tmp_path / "x"),
                                 sidecar=str(tmp_path / "y"))

    assert any(not p.passed and "kaboom" in p.detail for p in probes)


# --------------------------------------------------------------- canaries -----
def test_the_canary_probe_passes_once_they_are_planted(tmp_path):
    from cybersec_slm.cleaning import canary

    ds = tmp_path / "dataset.jsonl"
    ds.write_text(json.dumps({"id": "r1", "text": "real record"}) + "\n",
                  encoding="utf-8")
    side = str(tmp_path / "canaries.json")
    canary.plant(str(ds), count=2, out=side)

    probe = security._probe_canaries(str(ds), side)

    assert probe.passed
    assert "2" in probe.detail


def test_the_canary_probe_fails_when_a_release_has_none(tmp_path):
    """No evidence is not evidence of success: an untraceable release says so."""
    probe = security._probe_canaries(str(tmp_path / "no.jsonl"),
                                     str(tmp_path / "no.json"))

    assert not probe.passed


def test_the_canary_probe_fails_when_one_went_missing(tmp_path):
    from cybersec_slm.cleaning import canary

    ds = tmp_path / "dataset.jsonl"
    ds.write_text(json.dumps({"id": "r1", "text": "real"}) + "\n", encoding="utf-8")
    side = str(tmp_path / "canaries.json")
    info = canary.plant(str(ds), count=3, out=side)
    kept = [ln for ln in ds.read_text(encoding="utf-8").splitlines(True)
            if info["tokens"][0] not in ln]
    ds.write_text("".join(kept), encoding="utf-8")

    probe = security._probe_canaries(str(ds), side)

    assert not probe.passed
    assert "missing" in probe.detail


# -------------------------------------------------------------- checklist -----
def test_the_checklist_is_read_from_the_threat_model(tmp_path):
    doc = tmp_path / "docs" / "security-requirements.md"
    doc.parent.mkdir(parents=True)
    doc.write_text("# x\n\n## Prioritized checklist\n\n"
                   "- [x] **F1** done thing.\n"
                   "- [ ] **F2** undone thing.\n\n"
                   "## Related documents\n\n- not a checkbox\n", encoding="utf-8")

    rows = security.checklist(str(doc))

    assert rows == [{"done": True, "text": "**F1** done thing."},
                    {"done": False, "text": "**F2** undone thing."}]


def test_a_missing_threat_model_is_an_empty_checklist(tmp_path):
    assert security.checklist(str(tmp_path / "nope.md")) == []


def test_the_real_threat_model_parses(tmp_path):
    """Guards the parser against the document being reformatted."""
    import os as _os

    from cybersec_slm import core

    p = _os.path.join(core.data_root(), security.REQUIREMENTS_DOC)
    if not _os.path.exists(p):
        return
    rows = security.checklist(p)
    assert len(rows) >= 8
    assert any("F1" in r["text"] for r in rows)


# ------------------------------------------------------------- the page -------
def test_the_security_page_renders_every_control(tmp_path, monkeypatch):
    import pytest
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    page = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "src", "cybersec_slm", "dashboard", "pages", "7_Security.py")

    at = AppTest.from_file(page, default_timeout=60).run()

    assert not at.exception
    rendered = " ".join(str(df.value) for df in at.dataframe)
    for name in ["URL screen", "Licence gate", "Zip-bomb guard", "Binary scan",
                 "Hazard scan", "PII redaction", "Canary tokens"]:
        assert name in rendered, f"{name} missing from the page"
