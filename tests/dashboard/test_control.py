import sys
import time

from cybersec_slm.core import DEFAULT_PROFILE as PROFILE
from cybersec_slm.dashboard import control

DUMMY = [sys.executable, "-c", "import time; time.sleep(30)"]


def _use_root(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))


def test_status_idle_on_fresh_root(tmp_path, monkeypatch):
    _use_root(tmp_path, monkeypatch)
    st = control.status()
    assert st["running"] is False
    assert st["pid"] is None


def test_start_status_stop(tmp_path, monkeypatch):
    _use_root(tmp_path, monkeypatch)
    try:
        res = control.start(_command=DUMMY)
        assert res["ok"] is True and res["pid"]
        # control file written under logs/
        assert (tmp_path / "logs" / PROFILE / control.CONTROL_NAME).exists()
        st = control.status()
        assert st["running"] is True and st["pid"] == res["pid"]
        # double start is refused
        again = control.start(_command=DUMMY)
        assert again["ok"] is False and "already active" in again["error"]
    finally:
        stopped = control.stop()
    assert stopped["ok"] is True
    # allow the OS a moment to reap, then confirm idle
    for _ in range(20):
        if not control.status()["running"]:
            break
        time.sleep(0.1)
    assert control.status()["running"] is False


def test_status_resume_reflects_the_command_actually_launched(tmp_path, monkeypatch):
    """status() must report what is RUNNING, not what the caller asked for.

    A full run's argv is built per stage from that page's saved settings, so a
    saved ``resume: true`` on the Clean page puts ``--resume`` in the plan even
    when the caller passed ``resume=False``. status() used to echo the caller's
    flag, so it announced a fresh run while the pipeline resumed — and skipped
    every source in the ledger.
    """
    _use_root(tmp_path, monkeypatch)
    monkeypatch.setattr(control.settings_store, "get_stage",
                        lambda key: {"resume": True} if key == "clean" else {})
    monkeypatch.setattr(control, "_spawn_detached", lambda cmd, root, logs: 4242)
    try:
        control.start(stage="all", resume=False,
                      settings={"skip_source": True, "skip_ingest": True})
        st = control.status()
        assert st["resume"] is True, "a plan containing --resume must report resume=True"
    finally:
        control._clear_control()


def test_explicit_resume_false_overrides_a_saved_resume(tmp_path, monkeypatch):
    """An explicit override must be able to force a run to be fresh."""
    _use_root(tmp_path, monkeypatch)
    monkeypatch.setattr(control.settings_store, "get_stage",
                        lambda key: {"resume": True} if key == "clean" else {})
    plan = control.build_full_plan(
        {"skip_source": True, "skip_ingest": True, "resume": False}, resume=False)
    assert not any("--resume" in argv for argv in plan)


def test_status_resume_false_for_a_fresh_plan(tmp_path, monkeypatch):
    _use_root(tmp_path, monkeypatch)
    monkeypatch.setattr(control.settings_store, "get_stage", lambda key: {})
    monkeypatch.setattr(control, "_spawn_detached", lambda cmd, root, logs: 4243)
    try:
        control.start(stage="all", resume=False,
                      settings={"skip_source": True, "skip_ingest": True})
        assert control.status()["resume"] is False
    finally:
        control._clear_control()


def test_stale_control_reads_idle(tmp_path, monkeypatch):
    _use_root(tmp_path, monkeypatch)
    logs = tmp_path / "logs" / PROFILE
    logs.mkdir(parents=True, exist_ok=True)
    (logs / control.CONTROL_NAME).write_text(
        '{"pid": 999999, "started_at": "x", "resume": false}', encoding="utf-8")
    st = control.status()
    assert st["running"] is False
    assert st["stale"] is True


def test_reset_deletes_data_and_logs(tmp_path, monkeypatch):
    _use_root(tmp_path, monkeypatch)
    (tmp_path / "data" / PROFILE / "clean").mkdir(parents=True)
    (tmp_path / "data" / PROFILE / "clean" / "x.jsonl").write_text("{}", encoding="utf-8")
    (tmp_path / "logs" / PROFILE / "eda").mkdir(parents=True)
    (tmp_path / "logs" / PROFILE / "clean_report.csv").write_text("a", encoding="utf-8")
    res = control.reset()
    assert res["ok"] is True
    assert set(res["removed"]) == {"data", "logs"}
    assert res["skipped"] == []
    assert not (tmp_path / "data" / PROFILE).exists()
    assert not (tmp_path / "logs" / PROFILE).exists()


def test_reset_removes_readonly_files(tmp_path, monkeypatch):
    # Regression: rmtree(ignore_errors=True) silently left read-only files behind
    # on Windows, so a reset only half-cleared data/. It must be fully removed now.
    import os
    import stat

    _use_root(tmp_path, monkeypatch)
    (tmp_path / "data" / PROFILE / "raw").mkdir(parents=True)
    ro = tmp_path / "data" / PROFILE / "raw" / "locked.jsonl"
    ro.write_text("{}", encoding="utf-8")
    os.chmod(ro, stat.S_IREAD)           # read-only: the case that used to leak
    try:
        res = control.reset()
        assert res["ok"] is True
        assert "data" in res["removed"]
        assert res["skipped"] == []
        assert not (tmp_path / "data" / PROFILE).exists()
    finally:
        if ro.exists():
            os.chmod(ro, stat.S_IWRITE)


def test_reset_refused_while_running(tmp_path, monkeypatch):
    _use_root(tmp_path, monkeypatch)
    try:
        control.start(_command=DUMMY)
        res = control.reset()
        assert res["ok"] is False
        assert "stop the running pipeline" in res["error"]
        assert (tmp_path / "logs" / PROFILE / control.CONTROL_NAME).exists()
    finally:
        control.stop()


def _joined(cmd):
    return " ".join(str(c) for c in cmd)


def test_build_command_all_with_advanced_settings():
    cmd = control.build_command("all", settings={"workers": 4, "source_timeout": 600})
    assert "all --workers 4 --source-timeout 600" in _joined(cmd)


def test_build_command_ingest_sources():
    cmd = control.build_command("ingest", settings={"sources": "x.csv"})
    assert "ingest --sources x.csv" in _joined(cmd)


def test_build_command_eda_boolean_flag():
    cmd = control.build_command("eda", settings={"no_auto_rebalance": True})
    assert "eda --no-auto-rebalance" in _joined(cmd)


def test_build_command_drops_flags_a_stage_does_not_accept():
    cmd = control.build_command("clean", settings={"mode": "both", "purge_raw": True})
    s = _joined(cmd)
    assert "--mode" not in s            # mode is a source-only flag, not clean
    assert "--purge-raw" in s


def test_build_command_resume_from_param():
    cmd = control.build_command("ingest", resume=True)
    assert "--resume" in _joined(cmd)


def test_build_command_defaults_to_all():
    assert control.build_command()[3] == "all"


def test_build_command_source_flags_and_domains_list():
    cmd = control.build_command("source", settings={
        "mode": "both", "per_keyword": 8, "max_total": 25,
        "domains": ["Application Security", "Cloud Security"]})
    s = _joined(cmd)
    assert "source --mode both --per-keyword 8 --max-total 25" in s
    # --domains comes last and lists every value.
    assert s.endswith("--domains Application Security Cloud Security")


def test_build_command_no_crawler_flag_when_disabled():
    cmd = control.build_command("all", settings={"no_crawler": True})
    assert "--no-crawler" in _joined(cmd)
    # Crawler on (no_crawler False) emits nothing.
    cmd2 = control.build_command("all", settings={"no_crawler": False})
    assert "--no-crawler" not in _joined(cmd2)


def test_build_command_source_drops_unrelated_flags():
    cmd = control.build_command(
        "source", settings={"purge_raw": True, "dry_run": True})
    s = _joined(cmd)
    assert "--purge-raw" not in s      # not a source-stage flag
    assert "--dry-run" in s


def test_build_command_source_emits_run_limit_flags():
    cmd = control.build_command("source", settings={
        "workers": 8, "max_minutes": 5, "time_range": "month",
        "no_site_scope": True, "no_quality_filter": True})
    s = _joined(cmd)
    assert "--workers 8" in s          # enrichment pool size (now a source flag)
    assert "--max-minutes 5" in s
    assert "--time-range month" in s
    assert "--no-site-scope" in s
    assert "--no-quality-filter" in s


def test_build_command_source_no_enrich_flag():
    cmd = control.build_command("source", settings={"no_enrich": True})
    assert "--no-enrich" in _joined(cmd)
    # enrichment on (no_enrich False) emits nothing.
    cmd2 = control.build_command("source", settings={"no_enrich": False})
    assert "--no-enrich" not in _joined(cmd2)


def test_build_command_selective_ingest_domains():
    cmd = control.build_command("ingest", settings={
        "domains": ["Cryptography", "Cloud Security"]})
    s = _joined(cmd)
    assert s.endswith("--domains Cryptography Cloud Security")


def test_build_command_selective_clean_domains():
    cmd = control.build_command("clean", settings={"domains": ["Cryptography"]})
    assert "clean --domains Cryptography" in _joined(cmd)


def test_build_command_row_level_ingest_sources_only():
    cmd = control.build_command("ingest", settings={
        "sources_only": ["http://a", "http://b"]})
    s = _joined(cmd)
    # --sources-only comes after --domains and lists every value.
    assert s.endswith("--sources-only http://a http://b")


def test_build_command_row_level_clean_sources_only():
    cmd = control.build_command("clean", settings={
        "sources_only": ["Crypto/s1", "Crypto/s2"]})
    assert _joined(cmd).endswith("--sources-only Crypto/s1 Crypto/s2")


def test_build_command_sources_only_dropped_for_source_stage():
    cmd = control.build_command("source", settings={"sources_only": ["http://a"]})
    assert "--sources-only" not in _joined(cmd)


def test_build_command_domains_and_sources_only_order():
    cmd = control.build_command("ingest", settings={
        "domains": ["Crypto"], "sources_only": ["http://a"]})
    s = _joined(cmd)
    # both list flags emitted, domains before sources-only so nargs never collides
    assert "--domains Crypto --sources-only http://a" in s


def test_build_command_source_searxng_url_and_language():
    cmd = control.build_command("source", settings={
        "searxng_url": "http://host:8080", "language": "fr"})
    s = _joined(cmd)
    assert "--searxng-url http://host:8080" in s
    assert "--language fr" in s


def test_build_command_source_engines_and_target_per_domain():
    cmd = control.build_command("source", settings={
        "engines": "github,arxiv", "target_per_domain": 83})
    s = _joined(cmd)
    assert "--engines github,arxiv" in s
    assert "--target-per-domain 83" in s


def test_build_command_ingest_no_hazard_scan_flag():
    cmd = control.build_command("ingest", settings={"no_hazard_scan": True})
    assert "--no-hazard-scan" in _joined(cmd)
    cmd2 = control.build_command("ingest", settings={"no_hazard_scan": False})
    assert "--no-hazard-scan" not in _joined(cmd2)


def test_build_command_no_hazard_scan_dropped_for_clean_stage():
    cmd = control.build_command("clean", settings={"no_hazard_scan": True})
    assert "--no-hazard-scan" not in _joined(cmd)


def test_build_command_clean_tunables():
    cmd = control.build_command("clean", settings={
        "min_text_chars": 10, "max_text_chars": 5000, "garbage_max": 0.5,
        "repeat_max": 0.6, "near_dup_threshold": 0.9, "shingle_size": 3,
        "minhash_perm": 64, "allowed_langs": ["en", "fr"]})
    s = _joined(cmd)
    assert "--min-text-chars 10" in s
    assert "--max-text-chars 5000" in s
    assert "--garbage-max 0.5" in s
    assert "--repeat-max 0.6" in s
    assert "--near-dup-threshold 0.9" in s
    assert "--shingle-size 3" in s
    assert "--minhash-perm 64" in s
    assert s.endswith("--allowed-langs en fr")


def test_build_command_eda_taxonomy_agnostic_thresholds():
    cmd = control.build_command("eda", settings={
        "min_total_records": 100, "min_records_per_subdomain": 10,
        "max_source_share": 0.5, "max_drift": 0.3, "max_dup_rate": 0.2,
        "min_avg_tokens": 8.0, "max_topic_cv": 2.0, "min_subdomain_share": 0.02,
        "owner": "team-x"})
    s = _joined(cmd)
    assert "--min-total-records 100" in s
    assert "--min-records-per-subdomain 10" in s
    assert "--max-source-share 0.5" in s
    assert "--max-drift 0.3" in s
    assert "--max-dup-rate 0.2" in s
    assert "--min-avg-tokens 8.0" in s
    assert "--max-topic-cv 2.0" in s
    assert "--min-subdomain-share 0.02" in s
    assert "--owner team-x" in s


def test_build_command_eda_tunables_dropped_for_ingest_stage():
    cmd = control.build_command("ingest", settings={"min_total_records": 100})
    assert "--min-total-records" not in _joined(cmd)

