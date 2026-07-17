import json
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


# ------------------------------------------------------------------ PDFs -------
def _make_pdf(text: str) -> bytes:
    """A one-page PDF with `text` on it, built with the same lib the crawler uses."""
    import pymupdf
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), text)
    data = doc.tobytes()
    doc.close()
    return bytes(data)


def test_a_pdf_response_is_extracted_not_dropped():
    """The bug behind the Union Bank policy pages: a PDF is not a TextResponse, so
    parse() returned early and threw it away. Bank policy pages are indexes of
    PDF links, so the whole document set vanished."""
    from scrapy.http import Response

    body = _make_pdf("Risk Management Policy of the Bank. Board approved. "
                     "This clause governs operational risk appetite.")
    resp = Response(url="https://bank.test/en/common/policies/risk.pdf", body=body)
    spider = crawl_runner.SiteSpider(
        {"start_url": "https://bank.test/en/common/policies",
         "allow_prefix": "https://bank.test/en/common/", "license": "Own content",
         "description": "UBI Policies", "extractor": "default"})

    records = [r for r in spider.parse(resp) if isinstance(r, dict)]

    assert records, "the PDF produced no records"
    body_text = " ".join(r["text"] for r in records)
    assert "Risk Management Policy" in body_text
    assert all(r["license"] == "Own content" for r in records)
    assert all(r["url"].endswith("risk.pdf") for r in records)


def test_the_link_extractor_follows_pdf_links():
    """Scrapy's default deny_extensions includes 'pdf', so PDF links were never
    even extracted from the index page."""
    from scrapy.http import HtmlResponse

    html = (b"<html><body><a href='/en/common/policies/kyc.pdf'>KYC</a>"
            b"<a href='/en/common/policies/aml.pdf'>AML</a></body></html>")
    resp = HtmlResponse(url="https://bank.test/en/common/policies", body=html,
                        encoding="utf-8")
    spider = crawl_runner.SiteSpider(
        {"start_url": "https://bank.test/en/common/policies",
         "allow_prefix": "https://bank.test/en/common/", "license": "x",
         "description": "d", "extractor": "default"})

    followed = [r.url for r in spider.parse(resp)
                if hasattr(r, "url") and r.url.endswith(".pdf")]

    assert any("kyc.pdf" in u for u in followed)
    assert any("aml.pdf" in u for u in followed)


def test_a_non_pdf_binary_is_still_ignored():
    """Only PDFs are worth extracting; an image or zip is not a document."""
    from scrapy.http import Response

    resp = Response(url="https://bank.test/en/common/logo.png",
                    body=b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    spider = crawl_runner.SiteSpider(
        {"start_url": "https://bank.test/en/common/", "allow_prefix":
         "https://bank.test/en/common/", "license": "x", "description": "d"})

    assert [r for r in spider.parse(resp) if isinstance(r, dict)] == []


def test_an_empty_pdf_yields_no_record_but_does_not_crash():
    from scrapy.http import Response

    resp = Response(url="https://bank.test/en/common/blank.pdf",
                    body=_make_pdf(""))
    spider = crawl_runner.SiteSpider(
        {"start_url": "https://bank.test/en/common/", "allow_prefix":
         "https://bank.test/en/common/", "license": "x", "description": "d"})

    assert [r for r in spider.parse(resp) if isinstance(r, dict)] == []
