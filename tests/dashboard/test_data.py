"""Headless tests for the dashboard read layer (no Streamlit needed)."""

import json
import os
import pathlib
import sqlite3
import time

from cybersec_slm.core import DEFAULT_PROFILE as PROFILE
from cybersec_slm.dashboard import charts, data


def _seed(root: str) -> None:
    """Write a minimal but realistic set of pipeline artifacts under `root`."""
    logs = os.path.join(root, "logs", PROFILE)
    eda = os.path.join(logs, "eda")
    final = os.path.join(root, "data", PROFILE, "final")
    os.makedirs(eda, exist_ok=True)
    os.makedirs(final, exist_ok=True)

    def _run(ts, total, passed, dup, drift):
        return {
            "ts": ts, "passed": passed,
            "metrics": {
                "total": total, "num_subdomains": 2,
                "subdomains": {"vuln-mgmt": total - 1, "iam": 1},
                "subdomain_distribution": {"vuln-mgmt": 0.9, "iam": 0.1},
                "concentration": {"worst_share": 0.4, "subdomain": "iam", "source": "x"},
                "dup_rate": dup, "text_quality": {"avg_tokens": 120, "avg_chars": 600},
                "drift": {"available": True, "max_delta": drift, "subdomain": "iam"},
            },
            "violations": ([] if passed else
                           [{"severity": "blocker", "check": "volume", "message": "too few"}])
            + [{"severity": "warning", "check": "subdomain_volume", "message": "iam thin"}],
        }

    older = _run("2026-07-01T10:00:00", 900, False, 0.02, 0.0)
    latest = _run("2026-07-02T10:00:00", 1500, True, 0.011, 0.05)
    with open(os.path.join(eda, "run-20260701T100000.json"), "w", encoding="utf-8") as f:
        json.dump(older, f)
    with open(os.path.join(eda, "run-20260702T100000.json"), "w", encoding="utf-8") as f:
        json.dump(latest, f)
    with open(os.path.join(eda, "latest.json"), "w", encoding="utf-8") as f:
        json.dump(latest, f)

    with open(os.path.join(logs, "final_table.csv"), "w", encoding="utf-8", newline="") as f:
        f.write("Name,Sub-Domain,License,Total Lines\n"
                "nvd,vuln-mgmt,Public Domain,1400\n"
                "iam-docs,iam,CC-BY,100\n")

    with open(os.path.join(logs, "clean_report.csv"), "w", encoding="utf-8", newline="") as f:
        f.write("sub_domain,source,file,in,out,struct_dropped,exact_dups\n"
                "vuln-mgmt,nvd,a.jsonl,10,8,1,1\n"
                "TOTAL,,1 files,10,8,1,1\n")

    with open(os.path.join(logs, "normalize_report.json"), "w", encoding="utf-8") as f:
        json.dump({"counts": {"in": 10, "written": 8, "rejected": 1},
                   "paused_sources": []}, f)

    with open(os.path.join(logs, "completed_sources.txt"), "w", encoding="utf-8") as f:
        f.write("hf:a\nurl:b\npdf:c\n")

    with open(os.path.join(logs, "pipeline.999.log"), "w", encoding="utf-8") as f:
        f.write("14:00:00 === source: hf a ===\n14:00:01 done\n")

    con = sqlite3.connect(os.path.join(logs, "ingest_log.sqlite"))
    con.execute(
        "CREATE TABLE ingest (ts TEXT, kind TEXT, name TEXT, category TEXT, domain TEXT, "
        "description TEXT, source_url TEXT, origin_format TEXT, orig_mb REAL, jsonl_mb REAL, "
        "rows INTEGER, sha256 TEXT, license TEXT, status TEXT)"
    )
    con.execute(
        "INSERT INTO ingest (name, domain, orig_mb, rows, status) VALUES (?, ?, ?, ?, ?)",
        ("hf:a", "Application Security", 2.5, 10, "ok"),
    )
    con.execute(
        "INSERT INTO ingest (name, domain, orig_mb, rows, status) VALUES (?, ?, ?, ?, ?)",
        ("url:b", "Threat Intelligence", 1.5, 4, "ok"),
    )
    con.commit()
    con.close()

    manifest = {
        "record_count": 4, "unique_content_hashes": 4, "token_total": 480,
        "pipeline_version": "0.1.0", "git_commit": "abcdef1234", "dataset_sha256": "deadbeef",
        "domains": {"vuln": 3, "iam": 1}, "subdomains": {"vuln-mgmt": 3, "iam": 1},
        "sources": {"nvd": 3, "iam-docs": 1}, "licenses": {"Public Domain": 3, "CC-BY": 1},
        "record_types": {"cve": 3, "doc": 1}, "languages": {"en": 4},
    }
    with open(os.path.join(final, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f)

    recs = [
        {"id": "1", "source": "nvd", "domain_name": "vuln", "subdomain_name": "vuln-mgmt",
         "record_type": "cve", "lang": "en", "token_count": 120,
         "text": "Heap overflow in the parser allows remote code execution"},
        {"id": "2", "source": "nvd", "domain_name": "vuln", "subdomain_name": "vuln-mgmt",
         "record_type": "cve", "lang": "en", "token_count": 130,
         "text": "SQL injection in the login form leaks credentials"},
        {"id": "3", "source": "nvd", "domain_name": "vuln", "subdomain_name": "vuln-mgmt",
         "record_type": "cve", "lang": "en", "token_count": 110,
         "text": "Cross site scripting in the comment field"},
        {"id": "4", "source": "iam-docs", "domain_name": "iam", "subdomain_name": "iam",
         "record_type": "doc", "lang": "en", "token_count": 120,
         "text": "Rotate service account keys every ninety days"},
    ]
    with open(os.path.join(final, "dataset.jsonl"), "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
    with open(os.path.join(final, "rejected.jsonl"), "w", encoding="utf-8") as f:
        f.write(json.dumps({"id": "9", "source": "bad",
                            "reason": "domain not in allowlist"}) + "\n")


def test_reads_and_facets(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))

    assert data.data_root() == str(tmp_path)

    eda = data.latest_eda()
    assert eda["passed"] is True and eda["metrics"]["total"] == 1500

    hist = data.eda_history()
    assert len(hist) == 2 and hist[0]["ts"] < hist[1]["ts"]        # oldest first
    trend = charts.eda_trend_rows(hist)
    assert [r["total"] for r in trend] == [900, 1500]

    assert len(data.source_table()) == 2
    assert data.clean_report()["total"]["out"] == "8"
    assert data.normalize_report()["counts"]["written"] == 8
    assert data.manifest()["record_count"] == 4

    facets = data.dataset_facets()
    assert facets["subdomain"] == {"vuln-mgmt": 3, "iam": 1}
    assert set(facets) == set(data.FILTER_FIELDS)


def test_dataset_filter_search_paginate(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))

    allrecs = data.dataset_page()
    assert allrecs["match_count"] == 4 and allrecs["capped"] is False

    filtered = data.dataset_page(filters={"subdomain": "vuln-mgmt"})
    assert filtered["match_count"] == 3
    assert {r["id"] for r in filtered["rows"]} == {"1", "2", "3"}

    searched = data.dataset_page(search="injection")
    assert searched["match_count"] == 1 and searched["rows"][0]["id"] == "2"

    page1 = data.dataset_page(offset=0, limit=2)
    page2 = data.dataset_page(offset=2, limit=2)
    assert [r["id"] for r in page1["rows"]] == ["1", "2"]
    assert [r["id"] for r in page2["rows"]] == ["3", "4"]
    assert page2["match_count"] == 4                              # total, not page

    assert data.sidecar("rejected")[0]["reason"].startswith("domain")
    assert data.sidecar("nonsense") == []


def test_live_and_run_status(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))

    prog = data.live_progress()
    assert prog["completed"] == 3
    assert any("source: hf" in ln for ln in prog["log_tail"])

    assert data.run_status()["state"] == "running"               # log just written
    old = time.time() - 3600
    os.utime(os.path.join(tmp_path, "logs", PROFILE, "pipeline.999.log"),
             (old, old))
    assert data.run_status()["state"] == "idle"


def test_checkpoint_status(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))

    # No ledger yet -> no checkpoint to resume from.
    empty = data.checkpoint_status()
    assert empty == {"exists": False, "completed": 0, "total": empty["total"]}
    assert empty["exists"] is False

    # A ledger with N recorded sources -> exists, counted; total from the catalog.
    logs = tmp_path / "logs" / PROFILE
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "completed_sources.txt").write_text("hf:a\nurl:b\npdf:c\n",
                                                encoding="utf-8")
    monkeypatch.setattr(data, "_catalog_total", lambda: 5)
    ck = data.checkpoint_status()
    assert ck == {"exists": True, "completed": 3, "total": 5}


def _write_log(tmp_path, name, body):
    logs = tmp_path / "logs" / PROFILE
    logs.mkdir(parents=True, exist_ok=True)
    (logs / name).write_text(body, encoding="utf-8")


def test_run_phase_detects_clean(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _write_log(tmp_path, "pipeline.1.log",
               "x - ingest: 130 sources\n"
               "x - ingest: done ok=125\n"
               "x - clean: /data/raw -> /data/clean\n"
               "x - final global dedup over /data/clean\n")
    ph = data.run_phase()
    assert ph["phase"] == "clean"       # cross-source dedup folds into clean
    assert ph["index"] == 3 and ph["total"] == 5


def test_run_phase_detects_gate_failed(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _write_log(tmp_path, "pipeline.2.log",
               "x - eda: scanning /data/clean\n"
               "x - eda: total=186875 subdomains=12\n"
               "x:392 - EDA sufficiency gate FAILED: 1 blocker(s); loop back\n")
    ph = data.run_phase()
    assert ph["phase"] == "gate_failed"
    assert ph["terminal"] is True
    assert "blocker" in ph["detail"]


def test_run_phase_detects_schema(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _write_log(tmp_path, "pipeline.3.log",
               "x - eda: total=1000\n"
               "x - schema normalization -> data/final/dataset.jsonl\n"
               "x - normalize: input=/data/clean -> /data/final/dataset.jsonl\n")
    ph = data.run_phase()
    assert ph["phase"] == "schema"
    assert ph["index"] == 5


def test_run_phase_unknown_without_logs(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    assert data.run_phase()["phase"] == "unknown"


def test_run_phase_follows_pointer_not_newest_log(tmp_path, monkeypatch):
    """Phase comes from the orchestrator's log, named by the pointer file.

    During a parallel clean every worker writes its own pipeline.<pid>.log, and
    one of them is always newer than the (quiet) orchestrator log — as are the
    stub logs any cybersec_slm process drops into logs/. Picking newest-by-mtime
    reads a log with no stage markers and reports "Starting..." forever while the
    run is actually mid-clean.
    """
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs" / PROFILE
    logs.mkdir(parents=True, exist_ok=True)
    run_log = logs / "pipeline.100.log"
    run_log.write_text("x - ingest: done ok=125\n"
                       "x - clean: /data/raw -> /data/clean\n", encoding="utf-8")
    # A clean worker's log: non-empty, newer, and carrying no stage marker.
    worker = logs / "pipeline.200.log"
    worker.write_text("x - Dom/src/a.jsonl: in=5 out=5\n", encoding="utf-8")
    os.utime(run_log, (1_600_000_000, 1_600_000_000))
    os.utime(worker, (1_600_001_000, 1_600_001_000))          # newest by mtime
    (logs / "active_run_log.txt").write_text(str(run_log), encoding="utf-8")

    assert data.run_phase()["phase"] == "clean"


_TIMELINE_LOG = (
    "2026-07-16 10:00:00.000 | INFO | x - ingest: 130 sources\n"
    "2026-07-16 10:00:30.000 | INFO | x - ingest: done ok=125\n"
    "2026-07-16 10:10:00.000 | INFO | x - clean: /data/raw -> /data/clean\n"
    "2026-07-16 10:40:00.000 | INFO | x - eda: scanning /data/clean\n"
)


def test_stage_timeline_bounds_each_stage_by_the_next(tmp_path, monkeypatch):
    """A stage runs until the next one starts; the furthest reached runs to now."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _write_log(tmp_path, "pipeline.1.log", _TIMELINE_LOG)
    monkeypatch.setattr(data, "run_status", lambda: {"state": "idle"})

    tl = data.stage_timeline()
    assert [r["stage"] for r in tl] == ["ingest", "clean", "eda"]   # source skipped
    ingest, clean, eda = tl
    assert ingest["start_s"] == 0.0 and ingest["duration_s"] == 600.0   # -> clean
    assert clean["start_s"] == 600.0 and clean["duration_s"] == 1800.0  # -> eda
    # Idle: the last stage stops at the final log line, not at wall-clock now.
    assert eda["start_s"] == 2400.0 and eda["duration_s"] == 0.0
    assert [r["running"] for r in tl] == [False, False, False]


def test_stage_timeline_runs_the_live_stage_to_now(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _write_log(tmp_path, "pipeline.1.log", _TIMELINE_LOG)
    monkeypatch.setattr(data, "run_status", lambda: {"state": "running"})
    monkeypatch.setattr(data.time, "time",
                        lambda: data._parse_log_ts("2026-07-16 11:00:00"))

    eda = data.stage_timeline()[-1]
    assert eda["stage"] == "eda" and eda["running"] is True
    assert eda["duration_s"] == 1200.0          # 10:40 -> 11:00, still going


def test_stage_timeline_empty_without_a_run(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    assert data.stage_timeline() == []


def test_stage_timeline_rows_shape_the_chart_data():
    """Minutes for the x axis, state for the colour, a formatted duration."""
    rows = charts.stage_timeline_rows([
        {"stage": "clean", "label": "Clean", "start_s": 0.0, "end_s": 600.0,
         "duration_s": 600.0, "running": False},
        {"stage": "eda", "label": "EDA gate", "start_s": 600.0, "end_s": 690.0,
         "duration_s": 90.0, "running": True},
    ])
    assert [r["stage"] for r in rows] == ["Clean", "EDA gate"]
    assert rows[0]["start_min"] == 0.0 and rows[0]["end_min"] == 10.0
    assert rows[0]["state"] == "done" and rows[0]["duration"] == "10:00"
    assert rows[1]["state"] == "running" and rows[1]["duration"] == "1:30"


def test_stage_timeline_rows_empty_for_no_timeline():
    assert charts.stage_timeline_rows([]) == []


def test_live_rate_rows_are_deltas_over_real_elapsed_time():
    """The sampler records totals; the chart shows how fast the total moves."""
    rows = charts.live_rate_rows([
        {"t": 100.0, "value": 10.0},
        {"t": 102.0, "value": 20.0},        # +10 over 2s -> 5/s
        {"t": 103.0, "value": 23.0},        # +3 over 1s  -> 3/s
    ])
    assert [r["rate"] for r in rows] == [5.0, 3.0]
    assert [r["elapsed_s"] for r in rows] == [2.0, 3.0]


def test_live_rate_rows_clamp_a_shrinking_total():
    """final_global_dedup rewrites files in place, so a total can dip; a negative
    throughput is meaningless."""
    rows = charts.live_rate_rows([{"t": 0.0, "value": 50.0},
                                  {"t": 1.0, "value": 40.0}])
    assert [r["rate"] for r in rows] == [0.0]


def test_live_rate_rows_need_two_samples():
    assert charts.live_rate_rows([{"t": 0.0, "value": 1.0}]) == []
    assert charts.live_rate_rows([]) == []


def test_clean_eta_is_measured_in_bytes_not_source_count(tmp_path, monkeypatch):
    """Sources span KB to GB, so counting them projects nonsense; and only THIS
    run's work may set the rate, since the ledger spans every resume."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs" / PROFILE
    logs.mkdir(parents=True)
    # 4 sources of 100 bytes each; a resume already did 2 before this run began.
    monkeypatch.setattr(data, "_raw_sizes_by_sid",
                        lambda: {f"D/s{i}": 100 for i in range(4)})
    (logs / "cleaned_sources.txt").write_text("D/s0\nD/s1\nD/s2\n", encoding="utf-8")
    monkeypatch.setattr(data, "_resume_skipped", lambda: 2)   # s0, s1 were skipped
    monkeypatch.setattr(data, "_clean_workers", lambda: 1)

    # This run did s2 (100 bytes) in 10s -> 10 B/s. One source (100B) remains.
    eta, basis = data.clean_eta(10.0)
    assert basis == "clean-bytes"
    assert eta == 10.0            # 100 bytes / 10 B/s, NOT a source-count guess


def test_clean_eta_is_bounded_by_the_biggest_single_source(tmp_path, monkeypatch):
    """One file is cleaned by one worker, so the tail cannot be parallelised away."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs" / PROFILE
    logs.mkdir(parents=True)
    # Done: 400 bytes. Remaining: one huge 1000-byte source.
    monkeypatch.setattr(data, "_raw_sizes_by_sid",
                        lambda: {"D/done": 400, "D/huge": 1000})
    (logs / "cleaned_sources.txt").write_text("D/done\n", encoding="utf-8")
    monkeypatch.setattr(data, "_resume_skipped", lambda: 0)
    monkeypatch.setattr(data, "_clean_workers", lambda: 4)

    # 400 bytes in 10s -> 40 B/s across 4 workers -> 10 B/s per worker.
    # Linear would say 1000/40 = 25s; one worker really needs 1000/10 = 100s.
    eta, _basis = data.clean_eta(10.0)
    assert eta == 100.0


def test_clean_eta_names_the_dedup_tail_rather_than_claiming_zero(tmp_path,
                                                                  monkeypatch):
    """Every source cleaned but still in `clean` means the cross-source dedup tail.

    Its cost has nothing to do with the per-source rate, so reporting the 0 that
    "no sources remain" implies would claim the run had finished while a long pass
    was still running.
    """
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs" / PROFILE
    logs.mkdir(parents=True)
    monkeypatch.setattr(data, "_raw_sizes_by_sid", lambda: {"D/s0": 100})
    (logs / "cleaned_sources.txt").write_text("D/s0\n", encoding="utf-8")
    monkeypatch.setattr(data, "_resume_skipped", lambda: 0)

    eta, basis = data.clean_eta(10.0)
    assert eta is None and basis == "finalizing"


def test_clean_eta_has_no_rate_before_the_first_source_finishes(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    (tmp_path / "logs" / PROFILE).mkdir(parents=True)
    monkeypatch.setattr(data, "_raw_sizes_by_sid", lambda: {"D/s0": 100})
    monkeypatch.setattr(data, "_resume_skipped", lambda: 0)
    eta, basis = data.clean_eta(5.0)
    assert eta is None and basis == "clean-warmup"


def test_run_phase_falls_back_to_newest_log_without_pointer(tmp_path, monkeypatch):
    """No pointer (a CLI run, or one predating it): newest non-empty log still wins."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _write_log(tmp_path, "pipeline.7.log", "x - clean: /data/raw -> /data/clean\n")
    assert data.run_phase()["phase"] == "clean"


def test_stage_states_all_done_when_artifacts_present(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs" / PROFILE
    (logs / "eda").mkdir(parents=True)
    (logs / "completed_sources.txt").write_text("a\n", encoding="utf-8")
    (logs / "clean_report.csv").write_text(
        "sub_domain,source,file,in,out\nTOTAL,,1 files,10,8\n", encoding="utf-8")
    (logs / "eda" / "latest.json").write_text('{"passed": true}', encoding="utf-8")
    final = tmp_path / "data" / PROFILE / "final"
    final.mkdir(parents=True)
    (final / "manifest.json").write_text('{"record_count": 8}', encoding="utf-8")
    monkeypatch.setattr(data, "_catalog_total", lambda: 5)

    st = data.stage_states()
    assert set(st) == {"source", "ingest", "clean", "eda", "schema"}
    assert st["clean"]["state"] == "done"
    assert st["schema"]["state"] == "done"


def test_stage_states_gate_failed_marks_eda(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs" / PROFILE
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "pipeline.1.log").write_text(
        "x - eda: total=10\nx:1 - EDA sufficiency gate FAILED: 1 blocker\n",
        encoding="utf-8")
    assert data.stage_states()["eda"]["state"] == "failed"


def test_run_status_includes_phase(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _write_log(tmp_path, "pipeline.4.log", "x - final global dedup over /clean\n")
    assert data.run_status()["phase"]["phase"] == "clean"


def test_run_status_control_file_is_authoritative(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs" / PROFILE
    logs.mkdir(parents=True, exist_ok=True)
    # a recent, non-empty pipeline log would otherwise read as "running"...
    (logs / "pipeline.123.log").write_text("work\n", encoding="utf-8")
    # ...but a control file whose process is dead makes state authoritatively idle
    (logs / "pipeline_run.json").write_text(
        '{"pid": 999999, "started_at": "x", "resume": false}', encoding="utf-8")
    assert data.run_status()["state"] == "idle"


def test_run_status_running_when_control_pid_alive(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs" / PROFILE
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "pipeline_run.json").write_text(
        json.dumps({"pid": os.getpid(), "started_at": "x", "resume": False}),
        encoding="utf-8")   # this test process is alive
    assert data.run_status()["state"] == "running"


def test_run_status_ignores_empty_stub_log(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs" / PROFILE
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "pipeline.777.log").write_text("", encoding="utf-8")   # empty import stub
    assert data.run_status()["state"] == "idle"                    # not "running"


def test_pipeline_logs_excludes_dashboard_own_log(tmp_path, monkeypatch):
    # The dashboard process writes its own pipeline.<pid>.log on every rerun (the
    # live funnel loads the catalog each tick), so it is non-empty and the newest
    # by mtime. It must be excluded so phase/status follow the running pipeline's
    # log (a separate pid) instead of the dashboard's own chatter -> "Starting".
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs" / PROFILE
    logs.mkdir(parents=True, exist_ok=True)
    own = logs / f"pipeline.{os.getpid()}.log"
    run = logs / "pipeline.99999.log"
    run.write_text("clean stage marker\n", encoding="utf-8")
    # Make the dashboard's own log the newest by mtime.
    own.write_text("loaded 1020 sources from Sources.csv\n", encoding="utf-8")
    os.utime(run, (1, 1))

    picked = data._pipeline_logs()
    assert str(own) not in picked
    assert picked[-1] == str(run)


def test_raw_funnel_counts_records_on_disk_not_the_catalog(tmp_path, monkeypatch):
    """Raw Records must be counted, not taken from the catalog.

    The catalog's line totals were measured against the live corpus and found to
    be wrong by +149% (17,972,727 claimed vs 44,761,032 actually on disk): 242 of
    370 fetched sources had no catalog figure at all, and one source alone
    (Microsoft) was out by 9.5M records. Disk is the only honest answer.
    """
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    raw = tmp_path / "data" / PROFILE / "raw"
    (raw / "Cloud Security" / "src-a").mkdir(parents=True)
    (raw / "Cryptography" / "src-b").mkdir(parents=True)
    (raw / "Cloud Security" / "src-a" / "data.jsonl").write_text(
        '{"a":1}\n{"a":2}\n{"a":3}\n', encoding="utf-8")
    (raw / "Cryptography" / "src-b" / "data.jsonl").write_text(
        '{"b":1}\n{"b":2}\n', encoding="utf-8")
    # The catalog wildly disagrees with disk; disk must win.
    monkeypatch.setattr(data, "_catalog_lines_by_folder", lambda: {
        ("Cloud Security", "src-a"): (20_000_000, 40000.0),
        ("Cryptography", "src-b"): (2_000_000, 3000.0)})

    funnel = data.data_funnel(measure_size=True)
    assert funnel["raw"]["sources"] == 2                 # counted on disk
    assert funnel["raw"]["lines"] == 5                   # 3 + 2, counted on disk


def test_raw_funnel_counts_sources_the_catalog_never_measured(tmp_path, monkeypatch):
    """242 of 370 fetched sources had zero catalog lines, hiding 14.4M records."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    raw = tmp_path / "data" / PROFILE / "raw"
    (raw / "Threat Intelligence" / "uncatalogued").mkdir(parents=True)
    (raw / "Threat Intelligence" / "uncatalogued" / "d.jsonl").write_text(
        '{"a":1}\n{"a":2}\n{"a":3}\n{"a":4}\n', encoding="utf-8")
    monkeypatch.setattr(data, "_catalog_lines_by_folder", lambda: {})   # nothing measured

    funnel = data.data_funnel(measure_size=True)
    assert funnel["raw"]["sources"] == 1
    assert funnel["raw"]["lines"] == 4       # was 0 while the records sat on disk


def test_raw_funnel_cheap_path_defers_record_count(tmp_path, monkeypatch):
    """The 1s live fragment must not read 92 GB: the cheap path reports 0 and the
    Overview fills Records from the cached count (as it already does for Size)."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    raw = tmp_path / "data" / PROFILE / "raw"
    (raw / "Cloud Security" / "src-a").mkdir(parents=True)
    (raw / "Cloud Security" / "src-a" / "data.jsonl").write_text(
        '{"a":1}\n{"a":2}\n', encoding="utf-8")
    monkeypatch.setattr(data, "_catalog_lines_by_folder", lambda: {})

    funnel = data.data_funnel(measure_size=False)
    assert funnel["raw"]["sources"] == 1     # still live and cheap
    assert funnel["raw"]["lines"] == 0       # deferred to cached.raw_records


def test_raw_size_measures_only_the_jsonl_corpus(tmp_path, monkeypatch):
    """Raw size + file count describe the .jsonl corpus, not the fetch scratch.

    Some sources clone a whole git repo into data/raw (millions of files beside a
    single .jsonl). Only .jsonl is ever ingested or cleaned, so counting every
    file both reported clone scratch as ingested data and made the walk cost
    minutes.
    """
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    raw = tmp_path / "data" / PROFILE / "raw"
    src = raw / "Vulnerability Management" / "patrowl"
    (src / "repo" / "nested").mkdir(parents=True)
    (src / "data.jsonl").write_bytes(b"\0" * (2 * 1024 * 1024))
    # Clone scratch: never cleaned, so it is not part of the corpus.
    (src / "repo" / "README.md").write_bytes(b"\0" * (4 * 1024 * 1024))
    (src / "repo" / "nested" / "vuln.json").write_bytes(b"\0" * (8 * 1024 * 1024))

    rows = data.raw_table()
    assert len(rows) == 1
    assert rows[0]["files"] == 1                          # the .jsonl, not the scratch
    assert rows[0]["size_mb"] == 2.0                      # 12 MB of scratch excluded

    monkeypatch.setattr(data, "_catalog_lines_by_folder", lambda: {})
    assert data.data_funnel(measure_size=True)["raw"]["size_mb"] == 2.0


def test_count_jsonl_records_rereads_only_changed_files(tmp_path):
    """Counting data/clean re-reads a file only when its (mtime, size) changed.

    A cleaned .jsonl is written once and left alone, but the Overview refreshes
    its record count every 20s — and re-reading all of data/clean took 32s at
    9.5 GB, so the dashboard could never keep up with itself during a run.
    """
    root = tmp_path / "clean"
    (root / "Dom" / "src").mkdir(parents=True)
    f = root / "Dom" / "src" / "a.jsonl"
    fixed = 1_600_000_000                                    # pin mtime: exact identity
    # write_bytes, not write_text: on Windows text mode turns \n into \r\n, which
    # would change the byte length these assertions depend on.
    f.write_bytes(b'{"a":1}\n{"a":2}\n')                     # 16 bytes, 2 records
    os.utime(f, (fixed, fixed))
    assert data._count_jsonl_records(str(root)) == 2

    # Rewrite to 1 record at the SAME byte length and the same pinned mtime, so the
    # file's identity is unchanged. The stale answer proves it was not re-read —
    # exactly the work being skipped for gigabytes of already-settled output.
    f.write_bytes(b'{"abcdefgh":123}')                       # 16 bytes, 1 record
    os.utime(f, (fixed, fixed))
    assert data._count_jsonl_records(str(root)) == 2

    # A real append changes the size, so the memo is busted and the count is fresh.
    with open(f, "ab") as fh:
        fh.write(b'\n{"a":3}\n{"a":4}\n')
    assert data._count_jsonl_records(str(root)) == 3


def test_cleaned_funnel_counts_disk_not_the_clean_report(tmp_path, monkeypatch):
    """Cleaned Records is what is ON DISK, never the clean report's TOTAL.

    The report is a per-PASS statistic and cannot be the corpus size:

    * a --resume pass only holds the sources IT cleaned (the rest are skipped via
      the ledger), and the report is rewritten from that subset, so it understates
      a resumed corpus;
    * final_global_dedup deletes records from data/clean AFTER the report is
      written, so even a clean single pass overstates what is actually there.
    """
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    clean = tmp_path / "data" / PROFILE / "clean" / "Dom" / "src"
    clean.mkdir(parents=True)
    (clean / "a.jsonl").write_bytes(b'{"t":1}\n{"t":2}\n{"t":3}\n')      # 3 on disk

    # A report claiming only 1 record out — as a resumed pass would.
    logs = tmp_path / "logs" / PROFILE
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "clean_report.csv").write_text(
        "sub_domain,source,file,in,out\n"
        "Dom,src,Dom/src/a.jsonl,1,1\n"
        "TOTAL,,1 files,1,1\n", encoding="utf-8")

    funnel = data.data_funnel(measure_size=True)
    assert funnel["cleaned"]["lines"] == 3          # disk wins over the report's 1


def test_raw_funnel_zero_when_no_raw_on_disk(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))                                 # no data/raw/ created

    funnel = data.data_funnel()
    assert funnel["raw"]["sources"] == 0
    assert funnel["raw"]["lines"] == 0                   # not claimed without raw
    assert funnel["raw"]["size_mb"] == 0.0


def test_data_funnel_cheap_path_uses_catalog_size_not_disk_walk(tmp_path, monkeypatch):
    # The Overview funnel refreshes every second via measure_size=False: raw size
    # must come from the catalog (cheap), while the default path walks disk.
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    raw = tmp_path / "data" / PROFILE / "raw"
    (raw / "Cloud Security" / "src-a").mkdir(parents=True)
    (raw / "Cloud Security" / "src-a" / "data.jsonl").write_bytes(b"\0" * (5 * 1024 * 1024))
    monkeypatch.setattr(data, "_catalog_lines_by_folder", lambda: {
        ("Cloud Security", "src-a"): (20_000_000, 40000.0)})

    cheap = data.data_funnel(measure_size=False)
    assert cheap["raw"]["sources"] == 1
    # Records are deferred to cached.raw_records, never taken from the catalog's
    # 20M claim: it was 149% wrong on the live corpus.
    assert cheap["raw"]["lines"] == 0
    assert cheap["raw"]["size_mb"] == 40000.0            # catalog size, no disk walk

    full = data.data_funnel(measure_size=True)
    assert full["raw"]["size_mb"] == 5.0                 # measured on disk (5 MB)


def _seed_final(root, recs):
    """Write a data/final/dataset.jsonl with no manifest beside it."""
    final = root / "data" / PROFILE / "final"
    final.mkdir(parents=True, exist_ok=True)
    (final / "dataset.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")
    return final


def test_final_funnel_counts_the_dataset_when_no_manifest_exists(tmp_path, monkeypatch):
    """The bug: normalize writes the manifest only when the whole pass finishes.

    Until then the dataset is large and growing while the Final row read 0 sources
    and 0 records beside a real Size.
    """
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    data.final_stats.reset()
    final = _seed_final(tmp_path, [
        {"source": "alpha", "token_count": 10},
        {"source": "beta", "token_count": 15},
        {"source": "alpha", "token_count": 5},
    ])
    assert not (final / "manifest.json").exists()

    appended = data.data_funnel(measure_size=True)["appended"]

    assert appended["lines"] == 3
    assert appended["sources"] == 2
    assert appended["tokens"] == 30
    assert appended["size_mb"] > 0


def test_final_funnel_ignores_a_stale_manifest_in_favour_of_the_dataset(tmp_path,
                                                                        monkeypatch):
    """A manifest from an earlier run must not outvote the file on disk."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    data.final_stats.reset()
    final = _seed_final(tmp_path, [{"source": "alpha", "token_count": 10}])
    (final / "manifest.json").write_text(json.dumps(
        {"record_count": 999, "sources": {"stale": 1}, "token_total": 42}),
        encoding="utf-8")

    appended = data.data_funnel(measure_size=True)["appended"]

    assert appended["lines"] == 1          # not the manifest's 999
    assert appended["sources"] == 1        # not the manifest's "stale"
    assert appended["tokens"] == 10        # not the manifest's 42


def test_final_funnel_cheap_path_defers_the_scan(tmp_path, monkeypatch):
    """The 1s tick must not parse the corpus; the Overview fills it from cache."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    data.final_stats.reset()
    _seed_final(tmp_path, [{"source": "alpha", "token_count": 10}])

    appended = data.data_funnel(measure_size=False)["appended"]

    assert appended["lines"] == 0
    assert appended["sources"] == 0
    assert appended["tokens"] == 0
    assert appended["size_mb"] > 0         # a stat call, not a scan


def test_final_funnel_is_zero_with_no_dataset(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    data.final_stats.reset()

    appended = data.data_funnel(measure_size=True)["appended"]

    assert (appended["lines"], appended["sources"], appended["tokens"]) == (0, 0, 0)
    assert appended["size_mb"] == 0.0


def test_blank_license_links_returns_only_unresolved_rows_with_links(monkeypatch):
    monkeypatch.setattr(data, "catalog_rows", lambda: [
        {"Name": "Good", "Dataset Link": "http://good", "License": "MIT"},
        {"Name": "Blank", "Dataset Link": "http://blank", "License": ""},
        {"Name": "Unknown", "Dataset Link": "http://unk", "License": "Unknown"},
        {"Name": "ToVerify", "Dataset Link": "http://tv", "License": "to-verify"},
        {"Name": "BlankNoLink", "Dataset Link": "", "License": ""},
    ])
    links = data.blank_license_links()
    # licensed row excluded; unresolved rows with a link included; link-less dropped
    assert links == ["http://blank", "http://unk", "http://tv"]


def test_ingest_source_rows_keeps_file_order_and_link_less_rows(monkeypatch):
    monkeypatch.setattr(data, "catalog_rows", lambda: [
        {"Name": "Alpha", "Sub-Domain": "Cryptography", "Dataset Link": "http://a"},
        {"Name": "NoLink", "Sub-Domain": "Cloud Security", "Dataset Link": ""},
        {"Name": "Beta", "Sub-Domain": "Cryptography", "Dataset Link": "http://b"},
    ])
    rows = data.ingest_source_rows()
    # every catalog row is present, in Sources.csv file order (row numbers align)
    assert [r["id"] for r in rows] == ["http://a", "", "http://b"]
    assert rows[1]["id"] == ""                           # link-less row kept
    assert rows[0]["subdomain"] == "Cryptography"


def test_clean_source_rows_stable_sorted_with_folder_ids(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    raw = tmp_path / "data" / PROFILE / "raw"
    for dom, src in (("Cryptography", "zeta"), ("Cryptography", "alpha"),
                     ("Cloud Security", "beta")):
        (raw / dom / src).mkdir(parents=True)
        (raw / dom / src / "data.jsonl").write_text("{}\n", encoding="utf-8")
    (raw / "Cryptography" / "empty").mkdir(parents=True)  # no data -> not offered

    rows = data.clean_source_rows()
    # sorted by (sub-domain, source); id is the '<sub-domain>/<source>' folder path.
    # The empty folder (no .jsonl) is excluded: nothing to clean there.
    assert [r["id"] for r in rows] == [
        "Cloud Security/beta", "Cryptography/alpha", "Cryptography/zeta"]


def test_ingest_progress_uses_completed_ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    raw = tmp_path / "data" / PROFILE / "raw"
    (raw / "Cloud Security" / "src-a").mkdir(parents=True)
    (raw / "Cloud Security" / "src-a" / "data.jsonl").write_text("{}\n", encoding="utf-8")
    (raw / "Cryptography" / "src-b").mkdir(parents=True)
    (raw / "Cryptography" / "src-b" / "data.jsonl").write_text("{}\n", encoding="utf-8")
    logs = tmp_path / "logs" / PROFILE
    logs.mkdir(parents=True, exist_ok=True)
    # Ledger records more checked sources than produced folders (skips/failures).
    (logs / "completed_sources.txt").write_text(
        "hf:a\nurl:b\nurl:c\nkaggle:d\n", encoding="utf-8")
    monkeypatch.setattr(data, "_catalog_total", lambda: 10)

    prog = data.ingest_progress()
    assert prog == {"checked": 4, "with_data": 2, "total": 10}


def test_ingest_progress_falls_back_to_disk(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    raw = tmp_path / "data" / PROFILE / "raw"
    (raw / "Cryptography" / "src-b").mkdir(parents=True)   # no ledger present
    (raw / "Cryptography" / "src-b" / "data.jsonl").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(data, "_catalog_total", lambda: 10)

    prog = data.ingest_progress()
    assert prog == {"checked": 1, "with_data": 1, "total": 10}


def test_ingest_progress_excludes_empty_folders(tmp_path, monkeypatch):
    # A folder created during ingest that produced no records (no .jsonl) is not
    # counted as "produced data": with_data reflects data-bearing folders only.
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    raw = tmp_path / "data" / PROFILE / "raw"
    (raw / "Cloud Security" / "has-data").mkdir(parents=True)
    (raw / "Cloud Security" / "has-data" / "data.jsonl").write_text("{}\n", encoding="utf-8")
    (raw / "Cloud Security" / "empty").mkdir(parents=True)   # fetched, produced nothing
    monkeypatch.setattr(data, "_catalog_total", lambda: 10)

    prog = data.ingest_progress()
    assert prog["with_data"] == 1


def test_ingest_outcome_parses_log_and_ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs" / PROFILE
    logs.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(logs / "ingest_log.sqlite"))
    con.execute("CREATE TABLE ingest (name TEXT, status TEXT)")
    con.execute("INSERT INTO ingest VALUES (?, ?)", ("nsa-cnsa-2-0", "failed: crawl rc=0"))
    con.execute("INSERT INTO ingest VALUES (?, ?)", ("good-src", "ok"))
    con.commit()
    con.close()
    (logs / "pipeline.9.log").write_text(
        "2026-07-12 18:23 | INFO | x:1 -   FAILED demo-src: "
        "HTTPStatusError: Client error '403 Forbidden' for url 'http://x'\n"
        "2026-07-12 18:53 | ERROR | x:1 -   TIMEOUT slow-src: exceeded 1800s; abandoning\n"
        "2026-07-12 19:23 | INFO | x:1 - ingest: done ok=8 failed=5 skipped=0 "
        "rejected=3 timed_out=2\n", encoding="utf-8")

    out = data.ingest_outcome()
    assert out["summary"] == {"ok": 8, "failed": 5, "skipped": 0,
                              "rejected": 3, "timed_out": 2}
    by_src = {i["source"]: i for i in out["issues"]}
    assert by_src["demo-src"]["kind"] == "failed"
    assert by_src["demo-src"]["reason"] == "blocked (403 Forbidden)"
    assert by_src["slow-src"]["reason"] == "timed out (over 1800s)"
    assert by_src["nsa-cnsa-2-0"]["reason"] == "crawl returned nothing"
    assert "good-src" not in by_src                       # ok rows are not issues


def test_ingest_outcome_empty_without_artifacts(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    out = data.ingest_outcome()
    assert out == {"summary": None, "issues": []}


def test_sources_without_data_reconciles_catalog_to_disk(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    from cybersec_slm.ingestion import license_gate
    from cybersec_slm.ingestion import sources as srcs
    from cybersec_slm.sourcing import profiles

    # ingest_table() returns [] unless a catalog file exists, so the profile's
    # catalog has to be present even though load_descriptors is stubbed below.
    profiles.ensure()

    descs = [
        {"kind": "hf", "ref": "ownerA/ds", "domain": "Cloud Security"},      # has data
        {"kind": "kaggle", "ref": "ownerB/ds", "domain": "Cryptography"},    # license-denied
        {"kind": "pdf", "slug": "lonely-pdf", "domain": "Network Security"},  # no folder
    ]
    monkeypatch.setattr(srcs, "load_descriptors", lambda *a, **k: descs)
    monkeypatch.setattr(license_gate, "is_license_ok",
                        lambda d: (False, "non-commercial (nc)")
                        if (d.get("ref") or "").startswith("ownerB") else (True, "ok"))

    raw = tmp_path / "data" / PROFILE / "raw" / "Cloud Security" / "ownerA"
    raw.mkdir(parents=True)
    (raw / "f.jsonl").write_text('{"text": "x"}\n', encoding="utf-8")

    rows = data.sources_without_data()
    by = {r["source"]: r for r in rows}
    assert "ownerA" not in by                              # produced data -> excluded
    assert by["ownerB"]["type"] == "license"
    assert by["ownerB"]["reason"] == "non-commercial (nc)"
    assert by["lonely-pdf"]["type"] == "no records"        # fetched, nothing on disk


def test_fmt_duration():
    assert charts.fmt_duration(0) == "0:00"
    assert charts.fmt_duration(65) == "1:05"
    assert charts.fmt_duration(3661) == "1:01:01"
    assert charts.fmt_duration(None) == "-"


def test_fmt_hms():
    assert charts.fmt_hms(0) == "00:00:00"
    assert charts.fmt_hms(65) == "00:01:05"          # hours never dropped
    assert charts.fmt_hms(3661) == "01:01:01"
    assert charts.fmt_hms(-5) == "00:00:00"          # clamps negatives
    assert charts.fmt_hms(None) == "-"


def test_run_timing_ingest_linear_eta(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    monkeypatch.setattr(data, "_catalog_total", lambda: 4)     # 4 sources total
    logs = tmp_path / "logs" / PROFILE
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "completed_sources.txt").write_text("a\nb\n", encoding="utf-8")  # 2 done
    start = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 100))
    (logs / "pipeline_run.json").write_text(
        json.dumps({"pid": 999999, "started_at": start, "resume": False}),
        encoding="utf-8")
    (logs / "pipeline.5.log").write_text(
        f"{start}.000 | INFO | x:1 - ingest: 4 sources\n", encoding="utf-8")

    t = data.run_timing()
    assert t["basis"] == "ingest-linear"
    assert t["elapsed_s"] >= 99
    # 2 of 4 done -> remaining ≈ elapsed (linear): eta ≈ elapsed
    assert abs(t["eta_s"] - t["elapsed_s"]) < 2
    # projected total start-to-end = elapsed + remaining (≈ 2x elapsed here)
    assert abs(t["total_s"] - (t["elapsed_s"] + t["eta_s"])) < 1e-6


def test_run_timing_finalizing_during_tail(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs" / PROFILE
    logs.mkdir(parents=True, exist_ok=True)
    start = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 50))
    (logs / "pipeline.6.log").write_text(                       # no control file
        f"{start}.0 | INFO | x:1 - final global dedup over /clean\n", encoding="utf-8")
    t = data.run_timing()
    assert t["basis"] == "finalizing" and t["eta_s"] is None    # tail: no source ETA
    assert t["elapsed_s"] >= 49                                 # start from log line


def test_loss_breakdown(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs" / PROFILE
    (logs / "eda").mkdir(parents=True)
    (logs / "clean_report.csv").write_text(
        "sub_domain,source,file,in,excluded_no_text,struct_dropped,"
        "behavioral_flagged,near_dups,exact_dups,non_en_dropped,out\n"
        "Threat Intelligence,big,a.jsonl,1000,900,10,0,0,0,0,90\n"
        "Cryptography,small,b.jsonl,50,0,2,0,0,0,0,48\n"
        "TOTAL,,2 files,1050,900,12,0,0,0,0,138\n", encoding="utf-8")
    (logs / "normalize_report.json").write_text(json.dumps(
        {"counts": {"in": 138, "synthetic_excluded": 40, "near_dups": 5,
                    "exact_dups": 2, "rejected": 1, "written": 90}}), encoding="utf-8")
    (logs / "eda" / "latest.json").write_text(json.dumps(
        {"rebalanced": True, "metrics": {"total": 138},
         "metrics_after_rebalance": {"total": 120}}), encoding="utf-8")

    lb = data.loss_breakdown()
    assert lb["raw_in"] == 1050 and lb["clean_out"] == 138 and lb["final_written"] == 90
    mech = {s["mechanism"]: s["dropped"] for s in lb["stages"]}
    assert mech["no prose column (excluded_no_text)"] == 900
    assert mech["synthetic source excluded"] == 40
    assert mech["auto-rebalance (random downsample)"] == 18     # 138 - 120
    top = lb["per_source"][0]                                   # biggest loser first
    assert top["source"] == "big" and top["lost"] == 910
    assert top["kept_pct"] == 9.0
    assert top["top_drop_reason"] == "no prose column"


def test_loss_breakdown_empty_without_reports(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    lb = data.loss_breakdown()
    assert lb["raw_in"] == 0 and lb["per_source"] == []


def test_bare_root_degrades_gracefully(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))   # nothing seeded
    assert data.latest_eda() is None
    assert data.eda_history() == []
    assert data.source_table() == []
    assert data.manifest() is None
    assert data.dataset_facets() == {k: {} for k in data.FILTER_FIELDS}
    assert data.dataset_page() == {"rows": [], "match_count": 0, "capped": False,
                                   "total_scanned": 0}
    assert data.run_status()["state"] == "idle"
    assert data.live_progress()["completed"] == 0


# --------------------------------------------------------------- ingest table --
def _seed_ingest_table(tmp_path, monkeypatch):
    """Three catalogued sources: one with data, one license-denied, one empty."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    from cybersec_slm.ingestion import license_gate
    from cybersec_slm.ingestion import sources as srcs

    descs = [
        {"kind": "hf", "ref": "ownerA/ds", "domain": "Cloud Security",
         "url": "https://huggingface.co/datasets/ownerA/ds", "license": "MIT"},
        {"kind": "kaggle", "ref": "ownerB/ds", "domain": "Cryptography",
         "url": "https://kaggle.com/datasets/ownerB/ds", "license": "CC BY-NC"},
        {"kind": "pdf", "slug": "lonely-pdf", "domain": "Network Security",
         "url": "https://x.test/lonely-pdf.pdf", "license": "MIT"},
    ]
    monkeypatch.setattr(srcs, "load_descriptors", lambda *a, **k: descs)
    monkeypatch.setattr(license_gate, "is_license_ok",
                        lambda d: (False, "non-commercial (nc)")
                        if (d.get("ref") or "").startswith("ownerB") else (True, "ok"))

    # A catalog file must exist for the table to build (its path is checked).
    from cybersec_slm.sourcing import profiles
    catalog = pathlib.Path(profiles.catalog_path())
    catalog.parent.mkdir(parents=True, exist_ok=True)
    catalog.write_text(
        "Name,Sub-Domain,Dataset Link,Total Lines,JSONL Size (MB),License\n"
        "Owner A,Cloud Security,https://huggingface.co/datasets/ownerA/ds,500,12.5,MIT\n"
        "Owner B,Cryptography,https://kaggle.com/datasets/ownerB/ds,900,3.0,CC BY-NC\n"
        "Lonely,Network Security,https://x.test/lonely-pdf.pdf,10,0.5,MIT\n",
        encoding="utf-8")
    monkeypatch.setattr(data, "_catalog_path", lambda: str(catalog))
    monkeypatch.setattr(data, "_repo_root", lambda: str(tmp_path))

    raw = tmp_path / "data" / PROFILE / "raw" / "Cloud Security" / "ownerA"
    raw.mkdir(parents=True)
    (raw / "f.jsonl").write_text('{"text": "x"}\n', encoding="utf-8")


def test_ingest_table_joins_catalog_to_disk(tmp_path, monkeypatch):
    _seed_ingest_table(tmp_path, monkeypatch)
    rows = data.ingest_table()
    by = {r["source"]: r for r in rows}
    assert set(by) == {"ownerA", "ownerB", "lonely-pdf"}

    ok = by["ownerA"]
    assert ok["status"] == "ingested"
    assert ok["reason"] == ""
    assert ok["name"] == "Owner A"
    assert ok["sub-domain"] == "Cloud Security"
    assert ok["records"] == 500                  # from the catalog's Total Lines
    assert ok["files"] == 1                      # measured on disk
    assert ok["size_mb"] > 0
    assert ok["license"] == "MIT"

    assert by["ownerB"]["status"] == "license"
    assert by["ownerB"]["reason"] == "non-commercial (nc)"
    assert by["lonely-pdf"]["status"] == "no records"

    # A source with nothing on disk is never credited with catalog records.
    assert by["ownerB"]["records"] == 0
    assert by["lonely-pdf"]["records"] == 0

    # Ingested sources sort ahead of the ones that produced nothing.
    assert rows[0]["status"] == "ingested"


def test_ingest_table_uses_supplied_raw_rows_instead_of_walking(tmp_path, monkeypatch):
    _seed_ingest_table(tmp_path, monkeypatch)
    monkeypatch.setattr(data, "raw_table",
                        lambda: (_ for _ in ()).throw(AssertionError("walked disk")))
    rows = data.ingest_table(raw_rows=[{"sub-domain": "Cloud Security",
                                        "source": "ownerA", "files": 7,
                                        "size_mb": 99.0}])
    by = {r["source"]: r for r in rows}
    assert by["ownerA"]["files"] == 7
    assert by["ownerA"]["size_mb"] == 99.0
    # No measurement for this one -> falls back to the catalog's recorded size.
    assert by["ownerB"]["size_mb"] == 3.0


def test_sources_without_data_is_the_non_ingested_rows(tmp_path, monkeypatch):
    _seed_ingest_table(tmp_path, monkeypatch)
    missing = data.sources_without_data()
    by = {r["source"]: r for r in missing}
    assert "ownerA" not in by                     # produced data -> excluded
    assert by["ownerB"]["type"] == "license"
    assert by["lonely-pdf"]["type"] == "no records"
    assert set(by["ownerB"]) == {"sub-domain", "source", "type", "reason"}


def test_ingest_table_empty_without_a_catalog(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    monkeypatch.setattr(data, "_catalog_path", lambda: str(tmp_path / "nope.csv"))
    assert data.ingest_table() == []


# --------------------------------------------------------------- clean stats ---
_CLEAN_REPORT = (
    "sub_domain,source,file,in,mapped_text,excluded_no_text,sanitized,struct_fixed,"
    "struct_dropped,behavioral_flagged,exact_dups,near_dups,pii_redacted,translated,"
    "non_en_dropped,out\n"
    "Cloud Security,ownerA,a.jsonl,100,10,5,20,2,8,3,4,1,12,6,2,77\n"
    "Cloud Security,ownerA,b.jsonl,100,0,5,10,0,2,1,0,1,8,0,0,91\n"
    "Network Security,ownerC,c.jsonl,50,0,0,5,0,10,0,5,0,3,0,5,30\n"
    "TOTAL,,3 files,250,10,10,35,2,20,4,9,2,23,6,7,198\n"
)


def test_clean_stats_reads_every_counter(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs" / PROFILE
    logs.mkdir(parents=True)
    (logs / "clean_report.csv").write_text(_CLEAN_REPORT, encoding="utf-8")

    s = data.clean_stats()
    assert s["has_report"] is True
    assert s["files"] == 3
    c = s["counts"]
    assert c["in"] == 250 and c["out"] == 198
    assert c["pii_redacted"] == 23               # the headline the Clean page shows
    assert c["translated"] == 6
    assert c["exact_dups"] == 9 and c["near_dups"] == 2
    assert c["struct_dropped"] == 20
    assert c["excluded_no_text"] == 10
    assert s["kept_pct"] == 79.2                 # 198/250
    # Every counter the cleaning pass records is surfaced, not just in/out.
    assert set(c) == {col for col, _l, _h in data.CLEAN_COUNTERS}


def test_clean_stats_empty_without_a_report(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    s = data.clean_stats()
    assert s["has_report"] is False
    assert s["kept_pct"] == 0.0
    assert all(v == 0 for v in s["counts"].values())


def test_clean_table_aggregates_each_source_over_its_files(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs" / PROFILE
    logs.mkdir(parents=True)
    (logs / "clean_report.csv").write_text(_CLEAN_REPORT, encoding="utf-8")

    rows = data.clean_table()
    by = {r["source"]: r for r in rows}
    assert set(by) == {"ownerA", "ownerC"}

    a = by["ownerA"]                             # two files, summed
    assert a["in"] == 200 and a["out"] == 168
    assert a["pii_redacted"] == 20               # 12 + 8
    assert a["struct_dropped"] == 10             # 8 + 2
    assert a["kept_pct"] == 84.0
    assert a["sub-domain"] == "Cloud Security"

    assert by["ownerC"]["in"] == 50 and by["ownerC"]["non_en_dropped"] == 5
    assert rows[0]["source"] == "ownerA"         # biggest input first


def test_clean_table_empty_without_a_report(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    assert data.clean_table() == []
