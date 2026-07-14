"""control.build_full_plan: the ordered per-stage argv list for a full run."""

from cybersec_slm.dashboard import control, settings_store


def _use_root(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))


def _stage_keys(plan):
    return [argv[0] for argv in plan]


def test_full_plan_runs_five_stages_in_order(tmp_path, monkeypatch):
    _use_root(tmp_path, monkeypatch)
    plan = control.build_full_plan()
    assert _stage_keys(plan) == ["source", "ingest", "clean", "eda", "schema"]


def test_full_plan_uses_each_pages_saved_settings(tmp_path, monkeypatch):
    _use_root(tmp_path, monkeypatch)
    settings_store.save_stage("source", {"per_keyword": 8, "mode": "both"})
    settings_store.save_stage("ingest", {"workers": 4})
    settings_store.save_stage("eda", {"no_enforce": True})
    settings_store.save_stage("schema", {"fresh": True})
    by = {argv[0]: argv for argv in control.build_full_plan()}
    # Flags that were dropped by the flat `all` allowlist now reach their stage.
    assert "--per-keyword" in by["source"] and "8" in by["source"]
    assert "--mode" in by["source"] and "both" in by["source"]
    assert "--workers" in by["ingest"] and "4" in by["ingest"]
    assert "--no-enforce" in by["eda"]         # was silently dropped before
    assert "--fresh" in by["schema"]           # was silently dropped before


def test_full_plan_resume_skips_source_and_resumes_supported_stages(tmp_path, monkeypatch):
    _use_root(tmp_path, monkeypatch)
    plan = control.build_full_plan(resume=True)
    assert _stage_keys(plan) == ["ingest", "clean", "eda", "schema"]   # no source
    by = {argv[0]: argv for argv in plan}
    assert "--resume" in by["ingest"]
    assert "--resume" in by["clean"]
    assert "--resume" not in by["eda"]         # eda/schema do not accept --resume
    assert "--resume" not in by["schema"]


def test_full_plan_overrides_beat_saved_settings(tmp_path, monkeypatch):
    _use_root(tmp_path, monkeypatch)
    settings_store.save_stage("ingest", {"workers": 4})
    by = {argv[0]: argv for argv in control.build_full_plan({"workers": 16})}
    ing = by["ingest"]
    assert ing[ing.index("--workers") + 1] == "16"     # override wins over saved 4
