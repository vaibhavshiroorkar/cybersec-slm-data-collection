#!/usr/bin/env python3
"""Standalone Scrapy crawl runner - executed as a subprocess by scrape_html.crawl().

Runs in a fresh process (clean Twisted reactor) so it never conflicts with the
ingestion ProcessPoolExecutor. Reads one site's config from a JSON argv payload,
crawls same-domain pages under an allow-prefix, and writes JSONL records
{source, url, license, text} to out_path. Imports only Scrapy + stdlib.
"""

from __future__ import annotations

import json
import sys
from urllib.parse import urlparse

import scrapy
from scrapy.crawler import CrawlerProcess
from scrapy.http import TextResponse
from scrapy.linkextractors import LinkExtractor

MIN_TEXT = 200
# Ancestors whose text is boilerplate, excluded from the extracted body.
_STRIP = ("script", "style", "nav", "footer", "header", "svg", "noscript", "form")

# Extractor names accepted in the crawl config (cfg["extractor"]).
EXTRACTOR_DEFAULT = "default"
EXTRACTOR_TRAFILATURA = "trafilatura"
EXTRACTORS = (EXTRACTOR_DEFAULT, EXTRACTOR_TRAFILATURA)


def _title(response) -> str:
    return (response.css("title::text").get() or "").strip()


def extract_default(response) -> tuple[str, str]:
    """Strip known boilerplate tags, then join every remaining visible text node.

    Cheap and dependency-free, but it only knows about the eight tags in _STRIP:
    a menu, sidebar, cookie banner, breadcrumb trail, or footer that is not marked
    up as <footer> all survive into the body text.
    """
    not_ancestor = " or ".join(f"ancestor::{tag}" for tag in _STRIP)
    parts = response.xpath(f"//body//text()[not({not_ancestor})]").getall()
    return _title(response), "\n".join(t.strip() for t in parts if t.strip())


def extract_trafilatura(response) -> tuple[str, str]:
    """Main-content extraction via trafilatura (upstream adbar/trafilatura).

    Detects the article body rather than trusting tag names, so the boilerplate
    the default extractor cannot see is dropped. Optional: the crawl still runs
    without the dependency, falling back rather than failing a whole source.

    Falling back is also what happens when trafilatura finds no main content --
    it returns None on pages that are genuinely not articles (link indexes,
    landing pages), and taking that as "empty" would silently lose pages the
    default extractor would have kept.
    """
    try:
        import trafilatura
    except ImportError:
        logger_warn("trafilatura is not installed; using the default extractor "
                    "(install the 'crawl' extra: uv sync --extra crawl)")
        return extract_default(response)
    text = trafilatura.extract(response.text, url=getattr(response, "url", None),
                               include_comments=False, include_tables=True,
                               no_fallback=False)
    if not text:
        return extract_default(response)
    return _title(response), text.strip()


_EXTRACTORS = {EXTRACTOR_DEFAULT: extract_default,
               EXTRACTOR_TRAFILATURA: extract_trafilatura}

_warned: set = set()


def logger_warn(msg: str) -> None:
    """Warn once per message (this module imports only Scrapy + stdlib)."""
    if msg not in _warned:
        _warned.add(msg)
        print(f"crawl: {msg}", file=sys.stderr, flush=True)


def extract(response, extractor: str = EXTRACTOR_DEFAULT) -> tuple[str, str]:
    """Return ``(title, body-text)`` using the named extractor.

    An unknown name falls back to the default rather than raising: this runs in a
    detached subprocess per source, so a bad setting must not take a crawl down.
    """
    fn = _EXTRACTORS.get(extractor)
    if fn is None:
        logger_warn(f"unknown extractor {extractor!r}; using {EXTRACTOR_DEFAULT}")
        fn = extract_default
    return fn(response)


class SiteSpider(scrapy.Spider):
    name = "site"

    def __init__(self, cfg: dict, **kw):
        super().__init__(**kw)
        self.cfg = cfg
        parsed = urlparse(cfg["start_url"])
        # OffsiteMiddleware matches spider.allowed_domains against the bare
        # hostname (no port), while LinkExtractor(allow_domains=...) matches
        # against the full netloc (including port). Local test servers run on
        # 127.0.0.1:PORT, so these two need different values or one of them
        # silently filters out every same-site request.
        self.allowed_domains = [parsed.hostname]
        self.start_urls = [cfg["start_url"]]
        self._prefix = cfg["allow_prefix"]
        self._use_js = bool(cfg.get("use_js"))
        # Permit PDF links. Scrapy's LinkExtractor drops everything in
        # IGNORED_EXTENSIONS by default, which includes 'pdf', so a page that is an
        # index of PDF links (a bank's policies/disclosures pages are exactly this)
        # yielded no links and no records: "crawl failed rc=0". Keep the rest of
        # the ignore list (images, archives, media) so the crawler still does not
        # chase a logo or a zip.
        from scrapy.linkextractors import IGNORED_EXTENSIONS
        deny_ext = [e for e in IGNORED_EXTENSIONS if e != "pdf"]
        self._link_extractor = LinkExtractor(allow_domains=[parsed.netloc],
                                             deny_extensions=deny_ext)

    def start_requests(self):
        yield self._request(self.cfg["start_url"])

    def _request(self, url: str):
        meta = {"playwright": True} if self._use_js else {}
        return scrapy.Request(url, callback=self.parse, meta=meta,
                              errback=self._on_error, dont_filter=False)

    def _on_error(self, failure):
        self.logger.warning(f"fetch failed: {failure.request.url}")

    def parse(self, response):
        # A PDF response is not a TextResponse, so the HTML path below returns
        # early on it. Extract it here instead, or every bank policy and
        # disclosure document (all PDFs) would be fetched and thrown away.
        if response.body[:4] == b"%PDF" or response.url.lower().endswith(".pdf"):
            yield from self._parse_pdf(response)
            return
        if not isinstance(response, TextResponse):
            return
        title, text = extract(response, self.cfg.get("extractor",
                                                     EXTRACTOR_DEFAULT))
        if text and len(text) > MIN_TEXT:
            yield {"source": title or self.cfg["description"],
                   "url": response.url,
                   "license": self.cfg["license"],
                   "text": text}
        for link in self._link_extractor.extract_links(response):
            nu = link.url.split("#")[0]
            if nu.startswith(self._prefix):
                yield self._request(nu)

    def _parse_pdf(self, response):
        """One record per page of a PDF, extracted with pymupdf.

        Same extraction as ``scrape.scrape_pdf`` (the standalone pdf kind), so a
        PDF found by crawling is treated exactly like one catalogued directly. A
        page with no extractable text (a scanned image) is skipped, not errored."""
        try:
            import pymupdf
            doc = pymupdf.open(stream=response.body, filetype="pdf")
        except Exception as e:                       # noqa: BLE001
            self.logger.warning(f"pdf parse failed: {response.url}: {e}")
            return
        try:
            for page in doc:
                txt = page.get_text().strip()
                # Any non-empty page, matching scrape_pdf: the MIN_TEXT floor is
                # for HTML pages padded with boilerplate, whereas a PDF page is
                # already content. A scanned image page extracts to "" and is
                # skipped; the cleaning stage applies the real length floor.
                if txt:
                    yield {"source": self.cfg["description"],
                           "url": response.url,
                           "license": self.cfg["license"],
                           "text": txt}
        finally:
            doc.close()


def build_settings(cfg: dict) -> dict:
    settings = {
        "ROBOTSTXT_OBEY": True,
        "USER_AGENT": cfg["user_agent"],
        "CLOSESPIDER_PAGECOUNT": cfg["max_pages"],
        "CLOSESPIDER_TIMEOUT": cfg["close_timeout"],
        "DOWNLOAD_DELAY": cfg["download_delay"],
        "AUTOTHROTTLE_ENABLED": True,
        "CONCURRENT_REQUESTS_PER_DOMAIN": 4,
        "LOG_LEVEL": "WARNING",
        "TELNETCONSOLE_ENABLED": False,
        "RETRY_ENABLED": True,
        "RETRY_TIMES": 3,
        "RETRY_HTTP_CODES": [500, 502, 503, 504, 408, 429, 403],
        "FEEDS": {cfg["out_path"]: {"format": "jsonlines", "encoding": "utf-8",
                                    "overwrite": True}},
    }
    if cfg.get("use_js"):
        settings["TWISTED_REACTOR"] = "twisted.internet.asyncioreactor.AsyncioSelectorReactor"
        settings["DOWNLOAD_HANDLERS"] = {
            "http": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
            "https": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
        }
    return settings


def main(argv: list[str] | None = None) -> None:
    argv = argv if argv is not None else sys.argv[1:]
    cfg = json.loads(argv[0])
    process = CrawlerProcess(build_settings(cfg))
    process.crawl(SiteSpider, cfg=cfg)
    process.start()


if __name__ == "__main__":
    main()
