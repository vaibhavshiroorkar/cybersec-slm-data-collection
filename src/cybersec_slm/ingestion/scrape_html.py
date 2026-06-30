#!/usr/bin/env python3
"""Crawl openly-licensed cybersecurity websites -> JSONL (one record per page).

Static pages: httpx + selectolax (fast). JS-rendered pages: Playwright (chromium).
Respects robots.txt (urllib.robotparser). Same-domain BFS with page/depth caps.
``crawl`` is invoked per ``website`` source by the streaming worker
(:func:`cybersec_slm.ingestion.worker.process_source`).
"""

import json
import os
import time
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

from selectolax.parser import HTMLParser

from .common import HEADERS, ONE_MB, RAW_DATA, category_of, http_get, logger, sha256_file

BASE = RAW_DATA
UA = HEADERS["User-Agent"]


def _robots_checker(start_url):
    p = urlparse(start_url)
    rp = RobotFileParser()
    rp.set_url(f"{p.scheme}://{p.netloc}/robots.txt")
    try:
        rp.read()
        return lambda u: rp.can_fetch(UA, u)
    except Exception:
        return lambda u: True   # no robots.txt reachable -> allow


def _render_js(url):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        b = pw.chromium.launch()
        pg = b.new_page(user_agent=UA)
        pg.goto(url, timeout=30000, wait_until="domcontentloaded")
        html = pg.content()
        b.close()
    return html


def _get_html(url, use_js):
    if use_js:
        try:
            return _render_js(url)
        except Exception as ex:
            logger.warning(f"  JS render failed ({type(ex).__name__}); static fallback")
    return http_get(url).text


def _extract(html):
    tree = HTMLParser(html)
    for sel in ("script", "style", "nav", "footer", "header", "svg", "noscript", "form"):
        for node in tree.css(sel):
            node.decompose()
    title = tree.css_first("title")
    title = title.text(strip=True) if title else ""
    body = tree.body
    text = body.text(separator="\n", strip=True) if body else ""
    links = [a.attributes.get("href") for a in tree.css("a[href]")]
    return title, text, [h for h in links if h]


def crawl(domain, slug, start_url, lic, use_js, max_pages, allow_prefix, desc, log):
    folder = os.path.join(BASE, domain, slug)
    os.makedirs(folder, exist_ok=True)
    can_fetch = _robots_checker(start_url)
    host = urlparse(start_url).netloc
    seen, queue, n = set(), [start_url], 0
    out = os.path.join(folder, slug + ".jsonl")
    logger.info(f"=== WEBSITE: {desc} ({host}) ===")
    with open(out, "w", encoding="utf-8") as f:
        while queue and n < max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            if not can_fetch(url):
                continue
            try:
                html = _get_html(url, use_js)
            except Exception as ex:
                logger.warning(f"  fetch fail {url}: {type(ex).__name__}")
                continue
            title, text, links = _extract(html)
            if text and len(text) > 200:
                f.write(json.dumps({"source": title or desc, "url": url,
                                    "license": lic, "text": text},
                                   ensure_ascii=False) + "\n")
                n += 1
            for href in links:
                nu = urljoin(url, href).split("#")[0]
                if (urlparse(nu).netloc == host and nu.startswith(allow_prefix)
                        and nu not in seen and len(queue) < max_pages * 5):
                    queue.append(nu)
            time.sleep(0.3)   # politeness
    size = os.path.getsize(out)
    logger.info(f"  {slug}: {n} pages, {size/ONE_MB:.2f} MB")
    log.record(kind="website", name=slug, category=category_of("website"),
               domain=domain, description=desc, source_url=start_url,
               origin_format="html", jsonl_mb=round(size / ONE_MB, 1), rows=n,
               sha256=sha256_file(out), license=lic, status="ok")
