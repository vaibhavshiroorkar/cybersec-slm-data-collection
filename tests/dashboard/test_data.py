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


def test_raw_funnel_metrics_use_ingest_ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))

    funnel = data.data_funnel()
    assert funnel["raw"]["sources"] == 2
    assert funnel["raw"]["lines"] == 14
    assert funnel["raw"]["size_mb"] == 4.0


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
