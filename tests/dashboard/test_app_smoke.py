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

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DASH = os.path.join(_REPO, "src", "cybersec_slm", "dashboard")


def _seed_minimal(root: str) -> None:
    eda = os.path.join(root, "logs", "eda")
    final = os.path.join(root, "data", "final")
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


@pytest.mark.parametrize("script", ["app.py", "pages/1_Pipeline.py", "pages/2_Dataset.py"])
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
    at = AppTest.from_file(os.path.join(_DASH, "pages/3_Agent.py"), default_timeout=30)
    at.run()
    assert not at.exception
    assert any("uv sync --extra dashboard --extra agent" in info.value for info in at.info)
