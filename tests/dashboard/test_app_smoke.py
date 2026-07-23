"""Streamlit render smoke test — skips unless the `dashboard` extra is installed.

Uses streamlit.testing.v1.AppTest to run each script headlessly and assert it
renders without raising. Seeds a minimal data-root and leaves no pipeline log, so
run_status is 'idle' and the Pipeline page takes its non-fragment path.
"""

import json
import os

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

from cybersec_slm.core import DEFAULT_PROFILE as PROFILE

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DASH = os.path.join(_REPO, "src", "cybersec_slm", "dashboard")


def _seed_minimal(root: str) -> None:
    eda = os.path.join(root, "logs", PROFILE, "eda")
    final = os.path.join(root, "data", PROFILE, "final")
    os.makedirs(eda, exist_ok=True)
    os.makedirs(final, exist_ok=True)
    report = {"ts": "2026-07-02T10:00:00", "passed": True,
              "metrics": {"total": 1500, "num_subdomains": 2,
                          "subdomains": {"vuln-mgmt": 1499, "iam": 1},
                          "subdomain_distribution": {"vuln-mgmt": 0.99, "iam": 0.01},
                          "concentration": {"worst_share": 0.4, "subdomain": "iam",
                                            "source": "x"},
                          "dup_rate": 0.01,
                          "text_quality": {"avg_tokens": 120},
                          "drift": {"available": True, "max_delta": 0.03}},
              "violations": []}
    with open(os.path.join(eda, "latest.json"), "w", encoding="utf-8") as f:
        json.dump(report, f)
    with open(os.path.join(eda, "run-20260702T100000.json"), "w", encoding="utf-8") as f:
        json.dump(report, f)
    with open(os.path.join(final, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump({"record_count": 2, "domains": {"vuln": 2}, "subdomains": {"vuln-mgmt": 2},
                   "sources": {"nvd": 2}, "record_types": {"cve": 2}, "languages": {"en": 2},
                   "licenses": {"Public Domain": 2}}, f)
    with open(os.path.join(final, "dataset.jsonl"), "w", encoding="utf-8") as f:
        for i in (1, 2):
            f.write(json.dumps({"id": str(i), "source": "nvd", "domain_name": "vuln",
                                "subdomain_name": "vuln-mgmt", "record_type": "cve",
                                "lang": "en", "token_count": 120,
                                "text": f"vulnerability record number {i}"}) + "\n")


@pytest.mark.parametrize("script", ["app.py", "pages/1_Sourcing.py", "pages/2_Ingest.py",
                                    "pages/3_Clean.py", "pages/4_EDA.py", "pages/5_Schema.py"])
def test_page_renders_without_error(script, tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed_minimal(str(tmp_path))
    at = AppTest.from_file(os.path.join(_DASH, script), default_timeout=30)
    at.run()
    assert not at.exception


def test_agent_page_shows_setup_instructions_when_not_configured(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    _seed_minimal(str(tmp_path))
    at = AppTest.from_file(os.path.join(_DASH, "pages/6_Agent.py"), default_timeout=30)
    at.run()
    assert not at.exception
    assert any("uv sync --extra dashboard --extra agent" in info.value for info in at.info)


def test_overview_stage_pills_default_to_all_five_lit(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed_minimal(str(tmp_path))
    at = AppTest.from_file(os.path.join(_DASH, "app.py"), default_timeout=30)
    at.run()
    assert not at.exception
    pills = at.pills(key="overview_stage_pills")
    assert pills.value == ["Sourcing", "Ingest", "Clean", "EDA", "Schema"]


def test_reset_button_asks_to_confirm_before_deleting(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed_minimal(str(tmp_path))
    # This profile's corpus. Reset is scoped to it: it used to delete <root>/data
    # wholesale, which took every other profile's corpus with it.
    data_dir = os.path.join(str(tmp_path), "data", PROFILE)
    other = os.path.join(str(tmp_path), "data", "some-other-profile")
    os.makedirs(other)
    with open(os.path.join(other, "keep.jsonl"), "w", encoding="utf-8") as f:
        f.write('{"text": "a second profile corpus"}\n')
    at = AppTest.from_file(os.path.join(_DASH, "app.py"), default_timeout=30)
    at.run()
    reset_btn = next(b for b in at.button if b.label == "Reset")
    reset_btn.click().run()
    assert not at.exception
    # Clicking Reset alone must not have deleted anything yet -- it only asks.
    assert os.path.isdir(data_dir)
    assert any("permanently deletes" in w.value.lower() for w in at.warning)

    cancel_btn = next(b for b in at.button if b.label == "Cancel" and b.key == "cancel_reset")
    cancel_btn.click().run()
    assert not at.exception
    assert os.path.isdir(data_dir)          # cancel left everything in place

    # Confirming for real does delete data/.
    reset_btn = next(b for b in at.button if b.label == "Reset")
    reset_btn.click().run()
    yes_btn = next(b for b in at.button if b.label == "Yes, reset")
    yes_btn.click().run()
    assert not at.exception
    assert not os.path.isdir(data_dir)
    # The other profile is untouched. This is the whole point of scoping Reset:
    # resetting ubi used to destroy cybersec's corpus from a button that said
    # nothing about it.
    assert os.path.isfile(os.path.join(other, "keep.jsonl"))


def test_sourcing_page_saves_domain_name_and_subdomain_code(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed_minimal(str(tmp_path))
    from cybersec_slm.sourcing import catalog

    at = AppTest.from_file(os.path.join(_DASH, "pages/1_Sourcing.py"), default_timeout=30)
    at.run()
    assert not at.exception
    at.tabs[3].text_input(key="domain_name_input").set_value("MEDTECH")
    at.button(key="domain_name_save").click().run()
    assert not at.exception
    assert catalog.domain_name() == "MEDTECH"

    at.tabs[3].text_input(key="add_name").set_value("Physical Security")
    at.tabs[3].text_input(key="add_code").set_value("PHYSSEC")
    at.button(key="add_save").click().run()
    assert not at.exception
    cat = catalog.load()
    assert cat["Physical Security"]["code"] == "PHYSSEC"
    assert catalog.domain_name() == "MEDTECH"     # unaffected by the subdomain save


def test_live_strip_shows_progress_chart_while_running(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed_minimal(str(tmp_path))
    logs = os.path.join(str(tmp_path), "logs", PROFILE)
    os.makedirs(logs, exist_ok=True)
    with open(os.path.join(logs, "pipeline_run.json"), "w", encoding="utf-8") as f:
        json.dump({"pid": os.getpid(), "cmd": ["x"], "stage": "all",
                   "resume": False, "started_at": "2026-07-15 12:00:00"}, f)
    with open(os.path.join(logs, "completed_sources.txt"), "w", encoding="utf-8") as f:
        f.write("a\nb\n")
    from cybersec_slm.sourcing import profiles
    sources_dir = profiles.profile_dir()
    os.makedirs(sources_dir, exist_ok=True)
    with open(os.path.join(sources_dir, "Sources.csv"), "w", encoding="utf-8") as f:
        f.write("Name,Sub-Domain\na,D\nb,D\nc,D\nd,D\n")

    at = AppTest.from_file(os.path.join(_DASH, "app.py"), default_timeout=30)
    at.run()
    assert not at.exception
    at.run()          # a second fragment tick so the history buffer has 2+ points
    assert not at.exception
    assert at.session_state["_live_history"]["checked"] == [2, 2]


def test_overview_funnel_uses_legacy_data_api_without_measure_size_kwarg(monkeypatch):
    from cybersec_slm.dashboard import app

    def legacy_data_funnel():
        return {"raw": {"sources": 1, "lines": 2, "size_mb": 3.0},
                "cleaned": {"sources": 4, "lines": 5, "size_mb": 6.0},
                "appended": {"sources": 7, "lines": 8, "size_mb": 9.0}}

    monkeypatch.setattr(app.data, "data_funnel", legacy_data_funnel)

    funnel = app._data_funnel_snapshot(measure_size=False)

    assert funnel["raw"]["sources"] == 1
    assert funnel["cleaned"]["lines"] == 5
    assert funnel["appended"]["size_mb"] == 9.0


def test_stage_config_modal_opens_with_stage_widgets(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed_minimal(str(tmp_path))

    at = AppTest.from_file(os.path.join(_DASH, "app.py"), default_timeout=30)
    at.run()
    assert not at.exception
    # Each stage has an Advanced button on the Overview page.
    assert at.button(key="cfg_schema") is not None
    # Clicking it opens the stage's config modal, which exposes that stage's own
    # widgets (schema: fresh) and a Save button. (AppTest renders a dialog only on
    # the run its trigger fires, so the multi-step save round-trip is not testable
    # here; settings_store persistence is covered by its own tests.)
    at.button(key="cfg_schema").click().run()
    assert not at.exception
    assert at.checkbox(key="schema_fresh") is not None
    assert at.button(key="schema_modal_save") is not None


def test_stage_config_modal_source_exposes_domains(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed_minimal(str(tmp_path))

    at = AppTest.from_file(os.path.join(_DASH, "app.py"), default_timeout=30)
    at.run()
    assert not at.exception
    # The source modal now configures everything, including sub-domains and mode
    # that used to live on the Sourcing page.
    at.button(key="cfg_source").click().run()
    assert not at.exception
    assert at.multiselect(key="source_domains") is not None
    assert at.selectbox(key="source_mode") is not None
    assert at.button(key="source_modal_save") is not None


@pytest.mark.parametrize("script", ["pages/2_Ingest.py", "pages/3_Clean.py",
                                    "pages/4_EDA.py"])
def test_inspection_pages_have_no_run_button(script, tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed_minimal(str(tmp_path))
    at = AppTest.from_file(os.path.join(_DASH, script), default_timeout=30)
    at.run()
    assert not at.exception
    # Running moved to the Overview page; these pages are inspection only.
    assert not any(str(b.label).lower().startswith("run") for b in at.button)


def test_a_dimmed_stage_stays_dimmed_across_a_page_visit(tmp_path, monkeypatch):
    """Streamlit drops a widget's state as soon as a rerun does not render it, so
    visiting any other page reset the toggles and a stage turned off quietly came
    back on. The selection is persisted, not held in widget state."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed_minimal(str(tmp_path))

    at = AppTest.from_file(os.path.join(_DASH, "app.py"), default_timeout=30).run()
    at.pills(key="overview_stage_pills").set_value(["Clean", "EDA"]).run()
    assert not at.exception

    # A fresh script run is what a page visit and a restart both look like.
    again = AppTest.from_file(os.path.join(_DASH, "app.py"), default_timeout=30).run()

    assert not again.exception
    assert again.pills(key="overview_stage_pills").value == ["Clean", "EDA"]


def test_a_dimmed_stage_is_skipped_by_the_run_it_configures(tmp_path, monkeypatch):
    """The toggle has to reach the plan, not just the screen."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed_minimal(str(tmp_path))
    from cybersec_slm.dashboard import control

    at = AppTest.from_file(os.path.join(_DASH, "app.py"), default_timeout=30).run()
    at.pills(key="overview_stage_pills").set_value(["Clean", "EDA"]).run()

    saved = control.settings_store.get_stage("overview")
    assert saved["stages"] == ["Clean", "EDA"]


def test_the_pill_selection_is_per_profile(tmp_path, monkeypatch):
    """It is saved beside the per-stage settings, which are already namespaced."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed_minimal(str(tmp_path))
    from cybersec_slm.dashboard import control

    control.settings_store.save_stage("overview", {"stages": ["Clean"]},
                                      profile="cybersec")
    control.settings_store.save_stage("overview", {"stages": ["Schema"]},
                                      profile="ubi")

    assert control.settings_store.get_stage(
        "overview", profile="cybersec")["stages"] == ["Clean"]
    assert control.settings_store.get_stage(
        "overview", profile="ubi")["stages"] == ["Schema"]

