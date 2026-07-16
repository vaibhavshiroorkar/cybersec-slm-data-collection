"""The dashboard's profile switcher: it must actually switch, and lock mid-run.

Skips unless the `dashboard` extra is installed.
"""

import os

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_APP = os.path.join(_REPO, "src", "cybersec_slm", "dashboard", "app.py")


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    monkeypatch.delenv("CYBERSEC_SLM_PROFILE", raising=False)
    yield


def _app() -> AppTest:
    return AppTest.from_file(_APP, default_timeout=30)


def test_switcher_offers_every_profile_and_marks_the_active_one():
    from cybersec_slm.sourcing import profiles

    app = _app().run()
    assert not app.exception
    pick = app.selectbox(key="profile_pick")
    assert set(pick.options) >= {"cybersec", "ubi"}
    assert pick.value == profiles.active() == "ubi"


def test_picking_a_profile_persists_the_switch():
    from cybersec_slm.sourcing import profiles

    app = _app().run()
    app.selectbox(key="profile_pick").select("cybersec").run()
    assert not app.exception
    assert profiles.active() == "cybersec", "the switch must persist, not just render"


def test_switching_repoints_the_catalog_the_dashboard_reads():
    from cybersec_slm.dashboard import data
    from cybersec_slm.sourcing import profiles

    profiles.ensure("cybersec")
    profiles.ensure("ubi")
    # Give the two profiles visibly different catalogs. ubi seeds its own-content
    # rows; cybersec seeds none, so one hand-written row makes it distinguishable.
    with open(profiles.catalog_path("cybersec"), "a", encoding="utf-8") as f:
        f.write("OnlyInCyber,Network Security,d,https://x.test/a,1,Dataset,CSV,"
                ",,,,,MIT,,,,,,,\n")

    app = _app().run()
    assert "AML-KYC" in data.catalog_summary()["by_domain"]

    app.selectbox(key="profile_pick").select("cybersec").run()
    assert not app.exception
    summary = data.catalog_summary()
    assert summary["total"] == 1
    assert "Network Security" in summary["by_domain"]
    assert "AML-KYC" not in summary["by_domain"], "still reading ubi's catalog"


def test_switcher_is_locked_while_a_run_is_in_flight(monkeypatch):
    from cybersec_slm.dashboard import data

    monkeypatch.setattr(data, "run_status",
                        lambda: {"state": "running", "pid": 1, "phase": {}})
    app = _app().run()
    assert not app.exception
    assert app.selectbox(key="profile_pick").disabled, (
        "switching mid-run would finish the run against a different corpus")
