"""Headless tests for the agent's read-only tool wrappers (no Streamlit, no network)."""

import json
import os

from cybersec_slm.dashboard import agent_tools


def _seed(root: str) -> None:
    """Write a minimal but realistic set of pipeline artifacts under `root`."""
    logs = os.path.join(root, "logs")
    eda = os.path.join(logs, "eda")
    final = os.path.join(root, "data", "final")
    os.makedirs(eda, exist_ok=True)
    os.makedirs(final, exist_ok=True)

    report = {
        "ts": "2026-07-02T10:00:00", "passed": False,
        "metrics": {"total": 900, "num_subdomains": 2,
                    "dup_rate": 0.02, "text_quality": {"avg_tokens": 110}},
        "violations": [{"severity": "blocker", "check": "volume", "message": "too few records"},
                       {"severity": "warning", "check": "subdomain_volume", "message": "iam thin"}],
    }
    with open(os.path.join(eda, "latest.json"), "w", encoding="utf-8") as f:
        json.dump(report, f)

    with open(os.path.join(logs, "final_table.csv"), "w", encoding="utf-8", newline="") as f:
        f.write("Name,Sub-Domain,License,Total Lines\n"
                "nvd,vuln-mgmt,Public Domain,900\n")

    with open(os.path.join(logs, "clean_report.csv"), "w", encoding="utf-8", newline="") as f:
        f.write("sub_domain,source,file,in,out,struct_dropped,exact_dups\n"
                "vuln-mgmt,nvd,a.jsonl,10,8,1,1\n"
                "TOTAL,,1 files,10,8,1,1\n")

    with open(os.path.join(logs, "normalize_report.json"), "w", encoding="utf-8") as f:
        json.dump({"counts": {"in": 10, "written": 8, "rejected": 1}, "paused_sources": []}, f)

    with open(os.path.join(logs, "completed_sources.txt"), "w", encoding="utf-8") as f:
        f.write("hf:a\nurl:b\n")

    with open(os.path.join(logs, "pipeline.123.log"), "w", encoding="utf-8") as f:
        f.write("10:00:00 === source: hf a ===\n10:00:01 done\n")

    manifest = {
        "record_count": 4, "token_total": 480,
        "domains": {"vuln": 3, "iam": 1}, "subdomains": {"vuln-mgmt": 3, "iam": 1},
        "sources": {"nvd": 3, "iam-docs": 1}, "licenses": {"Public Domain": 3, "CC-BY": 1},
        "languages": {"en": 4},
    }
    with open(os.path.join(final, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f)

    recs = [
        {"id": "1", "source": "nvd", "domain_name": "vuln", "subdomain_name": "vuln-mgmt",
         "record_type": "cve", "lang": "en", "token_count": 120,
         "text": "Heap overflow in the parser allows remote code execution"},
        {"id": "2", "source": "iam-docs", "domain_name": "iam", "subdomain_name": "iam",
         "record_type": "doc", "lang": "en", "token_count": 90,
         "text": "Rotate service account keys every ninety days"},
    ]
    with open(os.path.join(final, "dataset.jsonl"), "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
    with open(os.path.join(final, "rejected.jsonl"), "w", encoding="utf-8") as f:
        f.write(json.dumps({"id": "9", "source": "bad",
                            "reason": "domain not in allowlist"}) + "\n")


def test_pipeline_status(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    status = agent_tools.get_pipeline_status()
    assert status["state"] == "running"
    assert status["sources_completed"] == 2
    assert any("source: hf" in ln for ln in status["log_tail"])


def test_eda_status(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    eda = agent_tools.get_eda_status()
    assert eda["available"] is True
    assert eda["passed"] is False
    assert [v["check"] for v in eda["blockers"]] == ["volume"]
    assert [v["check"] for v in eda["warnings"]] == ["subdomain_volume"]


def test_eda_status_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    assert agent_tools.get_eda_status() == {"available": False}


def test_manifest_summary(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    man = agent_tools.get_manifest_summary()
    assert man["available"] is True
    assert man["record_count"] == 4
    assert man["sources"] == {"nvd": 3, "iam-docs": 1}


def test_manifest_summary_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    assert agent_tools.get_manifest_summary() == {"available": False}


def test_source_table(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    rows = agent_tools.get_source_table()
    assert len(rows) == 1 and rows[0]["Name"] == "nvd"


def test_stage_reports(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    reports = agent_tools.get_stage_reports()
    assert reports["clean"]["out"] == "8"
    assert reports["normalize"]["counts"]["written"] == 8


def test_search_dataset_matches_and_trims(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    result = agent_tools.search_dataset(query="rotate")
    assert result["match_count"] == 1
    row = result["rows"][0]
    assert row["id"] == "2"
    assert row["text_excerpt"].startswith("Rotate service account keys")
    assert set(row) == {"id", "source", "subdomain", "record_type", "lang",
                        "token_count", "text_excerpt"}


def test_search_dataset_filters_by_facet(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    result = agent_tools.search_dataset(subdomain="iam")
    assert result["match_count"] == 1 and result["rows"][0]["id"] == "2"


def test_search_dataset_limit_clamped_up_from_zero(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    result = agent_tools.search_dataset(limit=0)
    assert len(result["rows"]) == 1   # clamped to at least 1, not 0


def test_rejected_or_dupes(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    rows = agent_tools.get_rejected_or_dupes("rejected")
    assert rows[0]["reason"].startswith("domain")
    assert agent_tools.get_rejected_or_dupes("duplicates") == []


def test_bare_root_degrades_gracefully(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))   # nothing seeded
    assert agent_tools.get_pipeline_status()["state"] == "idle"
    assert agent_tools.get_pipeline_status()["sources_completed"] == 0
    assert agent_tools.get_eda_status() == {"available": False}
    assert agent_tools.get_manifest_summary() == {"available": False}
    assert agent_tools.get_source_table() == []
    assert agent_tools.get_stage_reports() == {"clean": None, "normalize": None}
    assert agent_tools.search_dataset() == {"rows": [], "match_count": 0, "capped": False}
    assert agent_tools.get_rejected_or_dupes("rejected") == []
