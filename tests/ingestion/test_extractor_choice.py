"""Choosing how a crawled page becomes text: default vs trafilatura."""

import sys

import pytest
from scrapy.http import HtmlResponse

from cybersec_slm.ingestion import crawl_runner as cr

_HTML = b"""
<html><head><title>Advisory 42</title></head>
<body>
  <nav>Home Products Contact</nav>
  <div class="sidebar">Related: one two three</div>
  <div id="cookie">We use cookies. Accept?</div>
  <article><p>A remote code execution flaw affects the parser component.</p></article>
  <footer>Copyright 2026</footer>
</body></html>
"""


def _resp():
    return HtmlResponse(url="http://example.com/a", body=_HTML)


def test_default_extractor_keeps_boilerplate_the_tag_list_cannot_see():
    """The reason trafilatura is on offer: <nav>/<footer> go, the rest stays."""
    title, text = cr.extract(_resp(), cr.EXTRACTOR_DEFAULT)
    assert title == "Advisory 42"
    assert "remote code execution" in text
    assert "Home Products Contact" not in text        # <nav> is stripped
    assert "We use cookies" in text                   # a plain <div> is not
    assert "Related: one two three" in text


def test_unknown_extractor_falls_back_instead_of_killing_the_crawl():
    """This runs in a detached subprocess per source; a bad setting must not take
    a whole source down."""
    title, text = cr.extract(_resp(), "nonsense")
    assert title == "Advisory 42" and "remote code execution" in text


def test_trafilatura_missing_falls_back_to_default(monkeypatch):
    """The dependency is optional, so its absence is a fallback, not a failure."""
    monkeypatch.setitem(sys.modules, "trafilatura", None)   # import -> ImportError
    title, text = cr.extract(_resp(), cr.EXTRACTOR_TRAFILATURA)
    assert title == "Advisory 42" and "remote code execution" in text


def test_trafilatura_empty_result_falls_back_rather_than_losing_the_page(monkeypatch):
    """trafilatura returns None on pages that are not articles (link indexes,
    landing pages). Taking that as 'empty' would silently drop pages the default
    extractor would have kept."""
    class _Stub:
        @staticmethod
        def extract(*a, **k):
            return None

    monkeypatch.setitem(sys.modules, "trafilatura", _Stub)
    _title, text = cr.extract(_resp(), cr.EXTRACTOR_TRAFILATURA)
    assert "remote code execution" in text            # default's output, not ""


def test_trafilatura_result_is_used_when_it_finds_content(monkeypatch):
    class _Stub:
        @staticmethod
        def extract(*a, **k):
            return "  just the article body  "

    monkeypatch.setitem(sys.modules, "trafilatura", _Stub)
    title, text = cr.extract(_resp(), cr.EXTRACTOR_TRAFILATURA)
    assert title == "Advisory 42"
    assert text == "just the article body"            # stripped, boilerplate gone


@pytest.mark.parametrize("chosen", ["default", "trafilatura"])
def test_crawl_config_carries_the_chosen_extractor(tmp_path, monkeypatch, chosen):
    """The runner is a subprocess reading a JSON config, so the choice rides there."""
    from cybersec_slm.ingestion import scrape_html

    seen = {}

    def _fake_run(cmd, **kw):
        import json as _json
        seen.update(_json.loads(cmd[-1]))
        raise RuntimeError("stop before crawling")

    monkeypatch.setattr(scrape_html, "BASE", str(tmp_path))
    monkeypatch.setattr(scrape_html.subprocess, "run", _fake_run)
    with pytest.raises(RuntimeError):
        scrape_html.crawl("Dom", "slug", "http://example.com", "MIT", False, 5,
                          "/", "desc", log=None, extractor=chosen)
    assert seen["extractor"] == chosen


def test_extractor_env_var_sets_it_without_threading_a_flag(tmp_path, monkeypatch):
    from cybersec_slm.ingestion import scrape_html

    seen = {}

    def _fake_run(cmd, **kw):
        import json as _json
        seen.update(_json.loads(cmd[-1]))
        raise RuntimeError("stop")

    monkeypatch.setenv("CYBERSEC_SLM_EXTRACTOR", "trafilatura")
    monkeypatch.setattr(scrape_html, "BASE", str(tmp_path))
    monkeypatch.setattr(scrape_html.subprocess, "run", _fake_run)
    with pytest.raises(RuntimeError):
        scrape_html.crawl("Dom", "slug", "http://example.com", "MIT", False, 5,
                          "/", "desc", log=None)
    assert seen["extractor"] == "trafilatura"


def test_default_when_nothing_chooses(tmp_path, monkeypatch):
    from cybersec_slm.ingestion import scrape_html

    seen = {}

    def _fake_run(cmd, **kw):
        import json as _json
        seen.update(_json.loads(cmd[-1]))
        raise RuntimeError("stop")

    monkeypatch.delenv("CYBERSEC_SLM_EXTRACTOR", raising=False)
    monkeypatch.setattr(scrape_html, "BASE", str(tmp_path))
    monkeypatch.setattr(scrape_html.subprocess, "run", _fake_run)
    with pytest.raises(RuntimeError):
        scrape_html.crawl("Dom", "slug", "http://example.com", "MIT", False, 5,
                          "/", "desc", log=None)
    assert seen["extractor"] == "default"           # unchanged behaviour by default


def test_cli_offers_only_the_known_extractors():
    """Parse the flag; do NOT call cli.main here — main runs the real ingest
    stage, and a test that fetches the internet is exactly the kind of accident
    this suite is meant to prevent."""
    from cybersec_slm import cli

    args = cli.build_parser().parse_args(["ingest", "--extractor", "trafilatura"])
    assert args.extractor == "trafilatura"
    assert cli.build_parser().parse_args(["ingest"]).extractor is None  # unset

    with pytest.raises(SystemExit):                  # anything else is rejected
        cli.build_parser().parse_args(["ingest", "--extractor", "nonsense"])
