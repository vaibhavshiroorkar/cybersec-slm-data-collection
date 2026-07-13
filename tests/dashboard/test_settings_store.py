"""Persistent per-stage advanced settings store."""

from cybersec_slm.dashboard import settings_store


def _use_root(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))


def test_missing_file_reads_empty(tmp_path, monkeypatch):
    _use_root(tmp_path, monkeypatch)
    assert settings_store.load() == {}
    assert settings_store.get_stage("ingest") == {}
    assert settings_store.merged_all() == {}


def test_save_and_get_stage_round_trip(tmp_path, monkeypatch):
    _use_root(tmp_path, monkeypatch)
    settings_store.save_stage("ingest", {"workers": 8, "no_crawler": True})
    assert settings_store.get_stage("ingest") == {"workers": 8, "no_crawler": True}
    # persisted to the data root, outside data/ and logs/ (survives a Reset)
    assert (tmp_path / settings_store.FILE_NAME).exists()


def test_save_stage_updates_one_stage_only(tmp_path, monkeypatch):
    _use_root(tmp_path, monkeypatch)
    settings_store.save_stage("ingest", {"workers": 8})
    settings_store.save_stage("clean", {"purge_raw": True})
    assert settings_store.get_stage("ingest") == {"workers": 8}
    assert settings_store.get_stage("clean") == {"purge_raw": True}


def test_merged_all_combines_stages_with_all_winning(tmp_path, monkeypatch):
    _use_root(tmp_path, monkeypatch)
    settings_store.save_stage("ingest", {"workers": 8, "source_timeout": 600})
    settings_store.save_stage("clean", {"purge_raw": True})
    settings_store.save_stage("all", {"workers": 4})     # explicit all wins
    merged = settings_store.merged_all()
    assert merged["workers"] == 4                        # all overrides ingest
    assert merged["source_timeout"] == 600               # from ingest
    assert merged["purge_raw"] is True                   # from clean
