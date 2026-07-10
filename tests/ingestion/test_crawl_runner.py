import json
import os
import subprocess
import sys
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

import pytest
from scrapy.http import HtmlResponse

from cybersec_slm.ingestion import crawl_runner


def test_extract_strips_script_and_returns_title():
    html = (b"<html><head><title>Hello</title></head><body>"
            b"<nav>menu</nav><p>Real content here that is long enough.</p>"
            b"<script>var x = 1;</script></body></html>")
    resp = HtmlResponse(url="http://x/", body=html, encoding="utf-8")
    title, text = crawl_runner.extract(resp)
    assert title == "Hello"
    assert "Real content here" in text
    assert "var x" not in text
    assert "menu" not in text


@pytest.fixture
def local_site(tmp_path):
    (tmp_path / "index.html").write_text(
        "<html><head><title>Index</title></head><body>"
        "<p>" + "index page body long enough to pass the filter. " * 6 + "</p>"
        "<a href='page2.html'>next</a></body></html>", encoding="utf-8")
    (tmp_path / "page2.html").write_text(
        "<html><head><title>Two</title></head><body>"
        "<p>" + "second page body also long enough to keep it. " * 6 + "</p>"
        "</body></html>", encoding="utf-8")
    handler = partial(SimpleHTTPRequestHandler, directory=str(tmp_path))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}/"
    srv.shutdown()


def test_runner_crawls_local_site(local_site, tmp_path):
    out = tmp_path / "out.jsonl"
    cfg = {"start_url": local_site + "index.html", "allow_prefix": local_site,
           "max_pages": 10, "use_js": False, "out_path": str(out),
           "user_agent": "test-agent", "download_delay": 0.0,
           "close_timeout": 30, "license": "MIT", "description": "local"}
    proc = subprocess.run(
        [sys.executable, "-m", "cybersec_slm.ingestion.crawl_runner", json.dumps(cfg)],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert out.exists()
    recs = [json.loads(ln) for ln in out.read_text(encoding="utf-8").splitlines() if ln.strip()]
    urls = {r["url"] for r in recs}
    assert any("index.html" in u for u in urls)
    assert any("page2.html" in u for u in urls)
    assert all(r["license"] == "MIT" and len(r["text"]) > 200 for r in recs)
