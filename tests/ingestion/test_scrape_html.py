import json
import os
import subprocess

from cybersec_slm.ingestion import scrape_html


class _Log:
    def __init__(self):
        self.rows = []

    def record(self, **kw):
        self.rows.append(kw)


def test_crawl_records_failure_on_nonzero_exit(tmp_path, monkeypatch):
    monkeypatch.setattr(scrape_html, "BASE", str(tmp_path))

    def fake_run(*a, **k):
        return subprocess.CompletedProcess(a[0], returncode=1, stdout="", stderr="boom")

    monkeypatch.setattr(scrape_html.subprocess, "run", fake_run)
    log = _Log()
    scrape_html.crawl("Net", "site-a", "http://x/", "MIT", False, 10,
                      "http://x/", "desc", log)
    assert len(log.rows) == 1
    assert log.rows[0]["status"].startswith("failed")


def test_crawl_records_ok_and_writes_sidecar(tmp_path, monkeypatch):
    monkeypatch.setattr(scrape_html, "BASE", str(tmp_path))

    def fake_run(cmd, *a, **k):
        # emulate crawl_runner writing the FEEDS jsonl
        cfg = json.loads(cmd[-1])
        with open(cfg["out_path"], "w", encoding="utf-8") as f:
            f.write(json.dumps({"source": "t", "url": "http://x/", "license": "MIT",
                                "text": "x" * 300}) + "\n")
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(scrape_html.subprocess, "run", fake_run)
    log = _Log()
    scrape_html.crawl("Net", "site-b", "http://x/", "MIT", False, 10,
                      "http://x/", "desc", log)
    folder = os.path.join(str(tmp_path), "Net", "site-b")
    assert os.path.exists(os.path.join(folder, "site-b.jsonl"))
    assert os.path.exists(os.path.join(folder, "_SOURCE.json"))
    assert log.rows[0]["status"] == "ok"
    assert log.rows[0]["rows"] == 1
