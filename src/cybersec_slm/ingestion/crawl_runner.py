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


def extract(response) -> tuple[str, str]:
    """Return (title, body-text) with boilerplate nodes excluded.

    Parity with the previous selectolax extractor: drop script/style/nav/footer/
    header/svg/noscript/form, then join visible text on newlines.
    """
    title = (response.css("title::text").get() or "").strip()
    not_ancestor = " or ".join(f"ancestor::{tag}" for tag in _STRIP)
    parts = response.xpath(f"//body//text()[not({not_ancestor})]").getall()
    text = "\n".join(t.strip() for t in parts if t.strip())
    return title, text


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
        self._link_extractor = LinkExtractor(allow_domains=[parsed.netloc])

    def start_requests(self):
        yield self._request(self.cfg["start_url"])

    def _request(self, url: str):
        meta = {"playwright": True} if self._use_js else {}
        return scrapy.Request(url, callback=self.parse, meta=meta,
                              errback=self._on_error, dont_filter=False)

    def _on_error(self, failure):
        self.logger.warning(f"fetch failed: {failure.request.url}")

    def parse(self, response):
        if not isinstance(response, TextResponse):
            return
        title, text = extract(response)
        if text and len(text) > MIN_TEXT:
            yield {"source": title or self.cfg["description"],
                   "url": response.url,
                   "license": self.cfg["license"],
                   "text": text}
        for link in self._link_extractor.extract_links(response):
            nu = link.url.split("#")[0]
            if nu.startswith(self._prefix):
                yield self._request(nu)


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
