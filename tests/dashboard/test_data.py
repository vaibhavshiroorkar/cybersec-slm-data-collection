"""Headless tests for the dashboard read layer (no Streamlit needed)."""

import json
import os
import sqlite3
import time

from cybersec_slm.dashboard import charts, data


def _seed(root: str) -> None:
    """Write a minimal but realistic set of pipeline artifacts under `root`."""
    logs = os.path.join(root, "logs")
    eda = os.path.join(logs, "eda")
    final = os.path.join(root, "data", "final")
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
    os.utime(os.path.join(tmp_path, "logs", "pipeline.999.log"), (old, old))
    assert data.run_status()["state"] == "idle"


def test_checkpoint_status(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))

    # No ledger yet -> no checkpoint to resume from.
    empty = data.checkpoint_status()
    assert empty == {"exists": False, "completed": 0, "total": empty["total"]}
    assert empty["exists"] is False

    # A ledger with N recorded sources -> exists, counted; total from the catalog.
    logs = tmp_path / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "completed_sources.txt").write_text("hf:a\nurl:b\npdf:c\n",
                                                encoding="utf-8")
    monkeypatch.setattr(data, "_catalog_total", lambda: 5)
    ck = data.checkpoint_status()
    assert ck == {"exists": True, "completed": 3, "total": 5}


def _write_log(tmp_path, name, body):
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
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


def test_stage_states_all_done_when_artifacts_present(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs"
    (logs / "eda").mkdir(parents=True)
    (logs / "completed_sources.txt").write_text("a\n", encoding="utf-8")
    (logs / "clean_report.csv").write_text(
        "sub_domain,source,file,in,out\nTOTAL,,1 files,10,8\n", encoding="utf-8")
    (logs / "eda" / "latest.json").write_text('{"passed": true}', encoding="utf-8")
    final = tmp_path / "data" / "final"
    final.mkdir(parents=True)
    (final / "manifest.json").write_text('{"record_count": 8}', encoding="utf-8")
    monkeypatch.setattr(data, "_catalog_total", lambda: 5)

    st = data.stage_states()
    assert set(st) == {"source", "ingest", "clean", "eda", "schema"}
    assert st["clean"]["state"] == "done"
    assert st["schema"]["state"] == "done"


def test_stage_states_gate_failed_marks_eda(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs"
    logs.mkdir()
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
    logs = tmp_path / "logs"
    logs.mkdir()
    # a recent, non-empty pipeline log would otherwise read as "running"...
    (logs / "pipeline.123.log").write_text("work\n", encoding="utf-8")
    # ...but a control file whose process is dead makes state authoritatively idle
    (logs / "pipeline_run.json").write_text(
        '{"pid": 999999, "started_at": "x", "resume": false}', encoding="utf-8")
    assert data.run_status()["state"] == "idle"


def test_run_status_running_when_control_pid_alive(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "pipeline_run.json").write_text(
        json.dumps({"pid": os.getpid(), "started_at": "x", "resume": False}),
        encoding="utf-8")   # this test process is alive
    assert data.run_status()["state"] == "running"


def test_run_status_ignores_empty_stub_log(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "pipeline.777.log").write_text("", encoding="utf-8")   # empty import stub
    assert data.run_status()["state"] == "idle"                    # not "running"


def test_raw_funnel_counts_disk_sources_and_catalog_lines(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    # Two source folders on disk under data/raw/<sub-domain>/<source>/.
    raw = tmp_path / "data" / "raw"
    (raw / "Cloud Security" / "src-a").mkdir(parents=True)
    (raw / "Cryptography" / "src-b").mkdir(parents=True)
    # Line/size totals come from the catalog, not a live scan of the raw tree.
    monkeypatch.setattr(data, "catalog_totals", lambda: {
        "raw_lines": 22_000_000, "raw_size_mb": 43000.0,
        "cleaned_lines": 500, "cleaned_size_mb": 12.0})

    funnel = data.data_funnel()
    assert funnel["raw"]["sources"] == 2                 # counted on disk
    assert funnel["raw"]["lines"] == 22_000_000          # from the catalog
    assert funnel["raw"]["size_mb"] == 43000.0


def test_raw_funnel_zero_when_no_raw_on_disk(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))                                 # no data/raw/ created
    monkeypatch.setattr(data, "catalog_totals", lambda: {
        "raw_lines": 22_000_000, "raw_size_mb": 43000.0,
        "cleaned_lines": 0, "cleaned_size_mb": 0.0})

    funnel = data.data_funnel()
    assert funnel["raw"]["sources"] == 0
    assert funnel["raw"]["lines"] == 0                   # not claimed without raw
    assert funnel["raw"]["size_mb"] == 0.0


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
    raw = tmp_path / "data" / "raw"
    (raw / "Cryptography" / "zeta").mkdir(parents=True)
    (raw / "Cryptography" / "alpha").mkdir(parents=True)
    (raw / "Cloud Security" / "beta").mkdir(parents=True)

    rows = data.clean_source_rows()
    # sorted by (sub-domain, source); id is the '<sub-domain>/<source>' folder path
    assert [r["id"] for r in rows] == [
        "Cloud Security/beta", "Cryptography/alpha", "Cryptography/zeta"]


def test_ingest_progress_uses_completed_ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    raw = tmp_path / "data" / "raw"
    (raw / "Cloud Security" / "src-a").mkdir(parents=True)
    (raw / "Cryptography" / "src-b").mkdir(parents=True)
    logs = tmp_path / "logs"
    logs.mkdir()
    # Ledger records more checked sources than produced folders (skips/failures).
    (logs / "completed_sources.txt").write_text(
        "hf:a\nurl:b\nurl:c\nkaggle:d\n", encoding="utf-8")
    monkeypatch.setattr(data, "_catalog_total", lambda: 10)

    prog = data.ingest_progress()
    assert prog == {"checked": 4, "with_data": 2, "total": 10}


def test_ingest_progress_falls_back_to_disk(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    raw = tmp_path / "data" / "raw"
    (raw / "Cryptography" / "src-b").mkdir(parents=True)   # no ledger present
    monkeypatch.setattr(data, "_catalog_total", lambda: 10)

    prog = data.ingest_progress()
    assert prog == {"checked": 1, "with_data": 1, "total": 10}


def test_ingest_outcome_parses_log_and_ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs"
    logs.mkdir()
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

    descs = [
        {"kind": "hf", "ref": "ownerA/ds", "domain": "Cloud Security"},      # has data
        {"kind": "kaggle", "ref": "ownerB/ds", "domain": "Cryptography"},    # license-denied
        {"kind": "pdf", "slug": "lonely-pdf", "domain": "Network Security"},  # no folder
    ]
    monkeypatch.setattr(srcs, "load_descriptors", lambda *a, **k: descs)
    monkeypatch.setattr(license_gate, "is_license_ok",
                        lambda d: (False, "non-commercial (nc)")
                        if (d.get("ref") or "").startswith("ownerB") else (True, "ok"))

    raw = tmp_path / "data" / "raw" / "Cloud Security" / "ownerA"
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
    logs = tmp_path / "logs"
    logs.mkdir()
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
    logs = tmp_path / "logs"
    logs.mkdir()
    start = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 50))
    (logs / "pipeline.6.log").write_text(                       # no control file
        f"{start}.0 | INFO | x:1 - final global dedup over /clean\n", encoding="utf-8")
    t = data.run_timing()
    assert t["basis"] == "finalizing" and t["eta_s"] is None    # tail: no source ETA
    assert t["elapsed_s"] >= 49                                 # start from log line


def test_loss_breakdown(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs"
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
