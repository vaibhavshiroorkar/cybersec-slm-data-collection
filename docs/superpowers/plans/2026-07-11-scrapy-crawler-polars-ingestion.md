# Scrapy crawler swap + polars big-file conversion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hand-rolled `website` BFS crawler with Scrapy (run as an isolated per-site subprocess) and add a polars lazy fast path for converting large csv/parquet/jsonl files to JSONL, without changing any downstream contract.

**Architecture:** The public `scrape_html.crawl()` seam is preserved; its body becomes a subprocess launch of a new standalone `crawl_runner` module that owns a fresh Twisted reactor, so it never conflicts with the ingestion `ProcessPoolExecutor`. Polars is added purely inside `to_jsonl` as a fast path with pandas as the always-available fallback.

**Tech Stack:** Python 3.13, Scrapy, scrapy-playwright, polars, pytest, httpx, pandas.

## Global Constraints

- Python `>=3.13`.
- New core dependencies (in `pyproject.toml` `[project].dependencies`): `scrapy>=2.11`, `scrapy-playwright>=0.0.40`, `polars>=1.0`.
- Record schema for crawled/converted records: `{source, url, license, text}` plus any original columns.
- Crawl keeps the 200-character minimum text filter (`len(text) > 200`).
- The 5 GB output cap (`CAP_BYTES`) is enforced on converted JSONL.
- `scrape_html.crawl(domain, slug, start_url, lic, use_js, max_pages, allow_prefix, desc, log)` signature is unchanged (worker.py must not change).
- Polars is a performance fast path only: any import/scan failure falls back to the existing pandas/orjson path.
- Commit messages: no Claude co-author/attribution line. No em dashes in code, comments, or docs.
- Platform: Windows (use `sys.executable`, `os.path.join`, subprocess with `timeout`).

---

## File Structure

- Modify `pyproject.toml` - add three core deps.
- Modify `src/cybersec_slm/ingestion/common.py` - rename `BIG_CSV_BYTES` -> `BIG_FILE_BYTES`; add `_polars_enrich`, `_polars_to_jsonl`; route large csv/parquet/jsonl through polars in `to_jsonl` with pandas fallback.
- Create `src/cybersec_slm/ingestion/crawl_runner.py` - standalone Scrapy spider + `CrawlerProcess`, run via `python -m`. Imports only Scrapy + stdlib.
- Modify `src/cybersec_slm/ingestion/scrape_html.py` - reshape `crawl()` to spawn `crawl_runner` as a subprocess and handle its result; delete the BFS/robots/Playwright internals.
- Create `tests/ingestion/test_polars_convert.py` - polars parity, fallback, cap.
- Create `tests/ingestion/test_crawl_runner.py` - offline extraction + local-server crawl.
- Create `tests/ingestion/test_scrape_html.py` - `crawl()` success + failure handling.

---

## Task 1: Add dependencies

**Files:**
- Modify: `pyproject.toml` (the `[project].dependencies` list)

**Interfaces:**
- Produces: `scrapy`, `scrapy_playwright`, `polars` importable in the project environment.

- [ ] **Step 1: Add the three deps to core dependencies**

In `pyproject.toml`, inside `[project].dependencies`, add these lines next to the existing ingestion deps (after `"selectolax>=0.3.0",`):

```toml
    "scrapy>=2.11",             # website crawler engine (ingestion/crawl_runner.py)
    "scrapy-playwright>=0.0.40",# JS rendering for crawls flagged use_js (lazy)
    "polars>=1.0",              # lazy fast path for large csv/parquet/jsonl -> jsonl
```

- [ ] **Step 2: Sync the environment**

Run: `uv sync`
Expected: resolves and installs scrapy, scrapy-playwright, polars with no error.

- [ ] **Step 3: Verify imports**

Run: `uv run python -c "import scrapy, scrapy_playwright, polars; print(scrapy.__version__, polars.__version__)"`
Expected: prints two version strings, no ImportError.

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "build: add scrapy, scrapy-playwright, polars as core deps"
```

---

## Task 2: Polars big-file conversion path

**Files:**
- Modify: `src/cybersec_slm/ingestion/common.py`
- Test: `tests/ingestion/test_polars_convert.py`

**Interfaces:**
- Consumes: `CAP_BYTES`, `_TEXT_CANDIDATES`, `_QA_PAIRS`, `logger` (existing in common.py).
- Produces:
  - `BIG_FILE_BYTES: int` (replaces `BIG_CSV_BYTES`).
  - `_polars_enrich(lf: "pl.LazyFrame", meta: dict) -> "pl.LazyFrame"`.
  - `_polars_to_jsonl(original: str, jsonl: str, cap: int, meta: dict | None) -> int` (returns output byte size, or `cap + 1` when the output exceeds `cap` after removing it).
  - `to_jsonl(original, jsonl, cap=CAP_BYTES, *, meta=None) -> int` now routes large csv/parquet/jsonl through polars, falling back to pandas.

- [ ] **Step 1: Write the failing tests**

Create `tests/ingestion/test_polars_convert.py`:

```python
import json
import os

import polars as pl
import pytest

from cybersec_slm.ingestion import common


def _read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(ln) for ln in f if ln.strip()]


def test_polars_enrich_adds_provenance_and_text(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text("content,other\nhello world,x\nfoo,y\n", encoding="utf-8")
    out = tmp_path / "out.jsonl"
    meta = {"source": "S", "url": "http://u", "license": "MIT"}
    size = common._polars_to_jsonl(str(src), str(out), common.CAP_BYTES, meta)
    assert size > 0
    recs = _read_jsonl(out)
    assert len(recs) == 2
    assert recs[0]["source"] == "S"
    assert recs[0]["url"] == "http://u"
    assert recs[0]["license"] == "MIT"
    assert recs[0]["text"] == "hello world"       # derived from `content`
    assert recs[0]["other"] == "x"


def test_polars_matches_pandas_provenance(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text("body,n\nalpha,1\nbeta,2\n", encoding="utf-8")
    meta = {"source": "S", "url": "http://u", "license": "MIT"}
    pol = tmp_path / "pol.jsonl"
    common._polars_to_jsonl(str(src), str(pol), common.CAP_BYTES, meta)
    pan = tmp_path / "pan.jsonl"
    df = common.read_any(str(src))
    df = common.enrich_df(df, source="S", url="http://u", lic="MIT")
    common.write_jsonl(df, str(pan))
    keys = ("source", "url", "license", "text")
    pol_rows = [{k: r.get(k) for k in keys} for r in _read_jsonl(pol)]
    pan_rows = [{k: r.get(k) for k in keys} for r in _read_jsonl(pan)]
    assert pol_rows == pan_rows


def test_polars_cap_removes_oversize_output(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text("content\n" + "\n".join(f"row{i}" for i in range(100)) + "\n",
                   encoding="utf-8")
    out = tmp_path / "out.jsonl"
    ret = common._polars_to_jsonl(str(src), str(out), cap=10, meta={"source": "S"})
    assert ret == 11                    # cap + 1
    assert not os.path.exists(out)      # oversize output removed


def test_to_jsonl_falls_back_when_polars_fails(tmp_path, monkeypatch):
    # Force the polars route (threshold 0) then make polars raise; pandas must win.
    monkeypatch.setattr(common, "BIG_FILE_BYTES", 0)

    def boom(*a, **k):
        raise RuntimeError("polars unavailable")

    monkeypatch.setattr(common, "_polars_to_jsonl", boom)
    src = tmp_path / "in.csv"
    src.write_text("content,n\nhi,1\n", encoding="utf-8")
    out = tmp_path / "out.jsonl"
    size = common.to_jsonl(str(src), str(out),
                           meta={"source": "S", "url": "u", "license": "MIT"})
    assert size > 0
    recs = _read_jsonl(out)
    assert recs[0]["text"] == "hi"
    assert recs[0]["source"] == "S"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/ingestion/test_polars_convert.py -v`
Expected: FAIL - `AttributeError: module ... has no attribute '_polars_to_jsonl'` / `BIG_FILE_BYTES`.

- [ ] **Step 3: Rename the threshold constant**

In `src/cybersec_slm/ingestion/common.py`, change:

```python
# CSVs above this size stream row-by-row (constant RAM) instead of via pandas.
BIG_CSV_BYTES = 200 * 1024 * 1024
```

to:

```python
# Files above this size take the polars lazy fast path (or the CSV row-streamer
# fallback) instead of loading whole into pandas.
BIG_FILE_BYTES = 200 * 1024 * 1024
```

- [ ] **Step 4: Add the polars helpers**

In `src/cybersec_slm/ingestion/common.py`, add these two functions immediately above `def to_jsonl(`:

```python
def _polars_enrich(lf, meta: dict | None):
    """Add source/url/license + a derived text column to a lazy frame.

    Mirrors ``enrich_df`` so a polars-converted file carries the same provenance
    fields the cleaning stage expects, regardless of the original schema.
    """
    import polars as pl

    cols = set(lf.collect_schema().names())
    if not meta:
        return lf
    additions = []
    for field in ("source", "url", "license"):
        if field not in cols:
            additions.append(pl.lit(meta.get(field, "")).alias(field))
    if additions:
        lf = lf.with_columns(additions)
    if "text" not in cols:
        text_col = next((c for c in _TEXT_CANDIDATES if c in cols), None)
        if text_col is not None:
            lf = lf.with_columns(pl.col(text_col).cast(pl.Utf8).alias("text"))
        else:
            for q_col, a_col in _QA_PAIRS:
                if q_col in cols and a_col in cols:
                    lf = lf.with_columns(
                        (pl.col(q_col).cast(pl.Utf8) + pl.lit("\n\n")
                         + pl.col(a_col).cast(pl.Utf8)).alias("text"))
                    break
    return lf


def _polars_to_jsonl(original: str, jsonl: str, cap: int,
                     meta: dict | None) -> int:
    """Lazy-scan a large csv/parquet/jsonl and stream it to JSONL via polars.

    Returns the output byte size, or ``cap + 1`` (after removing the output) when
    it exceeds ``cap``. Raises for any unsupported extension or scan error so the
    caller can fall back to the pandas path.
    """
    import polars as pl

    low = original.lower()
    if low.endswith(".csv"):
        lf = pl.scan_csv(original, ignore_errors=True, infer_schema_length=1000)
    elif low.endswith(".parquet"):
        lf = pl.scan_parquet(original)
    elif low.endswith(".jsonl"):
        lf = pl.scan_ndjson(original)
    else:
        raise ValueError(f"polars fast path unsupported for {original}")
    lf = _polars_enrich(lf, meta)
    lf.sink_ndjson(jsonl)
    size = os.path.getsize(jsonl)
    if size > cap:
        os.remove(jsonl)
        return cap + 1
    return size
```

- [ ] **Step 5: Route large files through polars in `to_jsonl`**

In `src/cybersec_slm/ingestion/common.py`, replace the body of `to_jsonl`:

```python
def to_jsonl(original: str, jsonl: str, cap: int = CAP_BYTES,
             *, meta: dict | None = None) -> int:
    """Convert any supported file to JSONL. Big/wide CSVs stream (constant RAM).

    `meta` (source, url, license) is injected into every record so the cleaning
    stage finds the required provenance fields regardless of original schema.
    """
    if original.lower().endswith(".csv") and os.path.getsize(original) > BIG_CSV_BYTES:
        logger.debug(f"streaming big CSV {os.path.basename(original)}")
        return _stream_csv_to_jsonl(original, jsonl, cap, extra_fields=meta)
    df = read_any(original)
    if meta:
        df = enrich_df(df, source=meta.get("source", ""),
                       url=meta.get("url", ""), lic=meta.get("license", ""))
    return write_jsonl(df, jsonl)
```

with:

```python
def to_jsonl(original: str, jsonl: str, cap: int = CAP_BYTES,
             *, meta: dict | None = None) -> int:
    """Convert any supported file to JSONL.

    Large csv/parquet/jsonl take the polars lazy fast path (constant RAM, fast);
    a polars failure or an exotic format falls back to the pandas reader (and, for
    very large CSVs, the orjson row-streamer). `meta` (source, url, license) is
    injected into every record so the cleaning stage finds provenance regardless
    of the original schema.
    """
    low = original.lower()
    if (low.endswith((".csv", ".parquet", ".jsonl"))
            and os.path.getsize(original) > BIG_FILE_BYTES):
        try:
            return _polars_to_jsonl(original, jsonl, cap, meta)
        except Exception as ex:
            logger.warning(f"polars fast path failed for {os.path.basename(original)}: "
                           f"{type(ex).__name__}: {ex}; falling back to pandas")
    if low.endswith(".csv") and os.path.getsize(original) > BIG_FILE_BYTES:
        logger.debug(f"streaming big CSV {os.path.basename(original)}")
        return _stream_csv_to_jsonl(original, jsonl, cap, extra_fields=meta)
    df = read_any(original)
    if meta:
        df = enrich_df(df, source=meta.get("source", ""),
                       url=meta.get("url", ""), lic=meta.get("license", ""))
    return write_jsonl(df, jsonl)
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `uv run pytest tests/ingestion/test_polars_convert.py -v`
Expected: 4 passed.

- [ ] **Step 7: Run the existing common tests (no regression)**

Run: `uv run pytest tests/ingestion/test_common.py -v`
Expected: all pass (the `BIG_CSV_BYTES` rename does not break them; if any test references `BIG_CSV_BYTES`, update it to `BIG_FILE_BYTES`).

- [ ] **Step 8: Commit**

```bash
git add src/cybersec_slm/ingestion/common.py tests/ingestion/test_polars_convert.py
git commit -m "feat(ingest): polars lazy fast path for large csv/parquet/jsonl conversion"
```

---

## Task 3: Scrapy crawl runner module

**Files:**
- Create: `src/cybersec_slm/ingestion/crawl_runner.py`
- Test: `tests/ingestion/test_crawl_runner.py`

**Interfaces:**
- Produces:
  - `extract(response) -> tuple[str, str]` (title, boilerplate-stripped text).
  - `SiteSpider` (scrapy.Spider) parameterized by a `cfg` dict.
  - `build_settings(cfg: dict) -> dict`.
  - `main(argv: list[str] | None = None) -> None` - the `python -m` entry; `argv[0]` is a JSON config string with keys `start_url, allow_prefix, max_pages, use_js, out_path, user_agent, download_delay, close_timeout, license, description`.
  - Writing JSONL records `{source, url, license, text}` to `cfg["out_path"]`.

- [ ] **Step 1: Write the failing tests**

Create `tests/ingestion/test_crawl_runner.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/ingestion/test_crawl_runner.py -v`
Expected: FAIL - `ModuleNotFoundError: No module named 'cybersec_slm.ingestion.crawl_runner'`.

- [ ] **Step 3: Create the crawl runner module**

Create `src/cybersec_slm/ingestion/crawl_runner.py`:

```python
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
        host = urlparse(cfg["start_url"]).netloc
        self.allowed_domains = [host]
        self.start_urls = [cfg["start_url"]]
        self._prefix = cfg["allow_prefix"]
        self._use_js = bool(cfg.get("use_js"))
        self._link_extractor = LinkExtractor(allow_domains=[host])

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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/ingestion/test_crawl_runner.py -v`
Expected: 2 passed. (The local-site test performs a real crawl of two loopback pages.)

- [ ] **Step 5: Commit**

```bash
git add src/cybersec_slm/ingestion/crawl_runner.py tests/ingestion/test_crawl_runner.py
git commit -m "feat(ingest): standalone Scrapy crawl runner (subprocess, fresh reactor)"
```

---

## Task 4: Reshape scrape_html.crawl to use the subprocess

**Files:**
- Modify: `src/cybersec_slm/ingestion/scrape_html.py` (full rewrite of the module body)
- Test: `tests/ingestion/test_scrape_html.py`

**Interfaces:**
- Consumes: `crawl_runner` (Task 3) via subprocess; `common.HEADERS`, `common.RAW_DATA`, `common.category_of`, `common.count_lines`, `common.logger`, `common.sha256_file`, `common.ONE_MB`.
- Produces: `crawl(domain, slug, start_url, lic, use_js, max_pages, allow_prefix, desc, log) -> None` (unchanged signature). Writes `<slug>.jsonl` + `_SOURCE.json`; records one ingest-log row with `status="ok"` on success or `status="failed: ..."` otherwise.

- [ ] **Step 1: Write the failing tests**

Create `tests/ingestion/test_scrape_html.py`:

```python
import json
import os
import subprocess

import pytest

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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/ingestion/test_scrape_html.py -v`
Expected: FAIL - current `scrape_html` has no `subprocess` attribute / different `crawl` internals.

- [ ] **Step 3: Rewrite scrape_html.py**

Replace the entire contents of `src/cybersec_slm/ingestion/scrape_html.py` with:

```python
#!/usr/bin/env python3
"""Crawl openly-licensed cybersecurity websites -> JSONL (one record per page).

The crawl engine is Scrapy, run as an isolated subprocess
(:mod:`cybersec_slm.ingestion.crawl_runner`) so its Twisted reactor never
conflicts with the ingestion ProcessPoolExecutor. This module keeps the
``crawl`` seam the per-source worker calls
(:func:`cybersec_slm.ingestion.worker.process_source`): it launches the runner,
then records provenance + the ingest-log row exactly as the other scrapers do.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from urllib.parse import urlparse

from .common import (
    HEADERS,
    ONE_MB,
    RAW_DATA,
    category_of,
    count_lines,
    logger,
    sha256_file,
)

BASE = RAW_DATA
UA = HEADERS["User-Agent"]
CLOSE_TIMEOUT_S = 600        # Scrapy CLOSESPIDER_TIMEOUT (in-child budget)
SUBPROC_BUFFER_S = 120       # subprocess.run budget = close timeout + buffer
DOWNLOAD_DELAY_S = 0.3       # politeness delay between requests


def _source_file(folder: str, title: str, url: str, lic: str) -> None:
    with open(os.path.join(folder, "_SOURCE.json"), "w", encoding="utf-8") as f:
        json.dump({"source": title, "url": url, "license": lic}, f, indent=2)


def _record_failed(log, *, slug, domain, desc, start_url, lic, status) -> None:
    log.record(kind="website", name=slug, category=category_of("website"),
               domain=domain, description=desc, source_url=start_url,
               origin_format="html", license=lic, status=status)


def crawl(domain, slug, start_url, lic, use_js, max_pages, allow_prefix, desc, log):
    folder = os.path.join(BASE, domain, slug)
    os.makedirs(folder, exist_ok=True)
    out = os.path.join(folder, slug + ".jsonl")
    cfg = {
        "start_url": start_url, "allow_prefix": allow_prefix,
        "max_pages": int(max_pages), "use_js": bool(use_js), "out_path": out,
        "user_agent": UA, "download_delay": DOWNLOAD_DELAY_S,
        "close_timeout": CLOSE_TIMEOUT_S, "license": lic, "description": desc,
    }
    logger.info(f"=== WEBSITE: {desc} ({urlparse(start_url).netloc}) ===")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "cybersec_slm.ingestion.crawl_runner",
             json.dumps(cfg)],
            capture_output=True, text=True,
            timeout=CLOSE_TIMEOUT_S + SUBPROC_BUFFER_S)
    except subprocess.TimeoutExpired:
        logger.error(f"  crawl timed out: {slug}")
        _record_failed(log, slug=slug, domain=domain, desc=desc,
                       start_url=start_url, lic=lic, status="failed: timeout")
        return

    if (proc.returncode != 0 or not os.path.exists(out)
            or os.path.getsize(out) == 0):
        logger.error(f"  crawl failed: {slug} (rc={proc.returncode})")
        _record_failed(log, slug=slug, domain=domain, desc=desc,
                       start_url=start_url, lic=lic,
                       status=f"failed: crawl rc={proc.returncode}")
        return

    _source_file(folder, desc, start_url, lic)
    n = count_lines(out)
    size = os.path.getsize(out)
    logger.info(f"  {slug}: {n} pages, {size / ONE_MB:.2f} MB")
    log.record(kind="website", name=slug, category=category_of("website"),
               domain=domain, description=desc, source_url=start_url,
               origin_format="html", jsonl_mb=round(size / ONE_MB, 1), rows=n,
               sha256=sha256_file(out), license=lic, status="ok")
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/ingestion/test_scrape_html.py -v`
Expected: 2 passed.

- [ ] **Step 5: Verify the worker still imports and dispatches website sources**

Run: `uv run pytest tests/ingestion/test_worker.py tests/ingestion/test_v2_pipeline_wiring.py -v`
Expected: all pass (worker.py is unchanged; the `website` branch still calls `scrape_html.crawl` with the same arguments).

- [ ] **Step 6: Commit**

```bash
git add src/cybersec_slm/ingestion/scrape_html.py tests/ingestion/test_scrape_html.py
git commit -m "feat(ingest): swap website crawler to Scrapy subprocess, drop BFS crawler"
```

---

## Task 5: Regression sweep + lint

**Files:**
- No source changes expected; fix any fallout surfaced here.

- [ ] **Step 1: Run the full ingestion + dashboard test suites**

Run: `uv run pytest tests/ingestion tests/dashboard -v`
Expected: all pass. If a test referenced `BIG_CSV_BYTES`, update it to `BIG_FILE_BYTES` and re-run.

- [ ] **Step 2: Lint the changed modules**

Run: `uv run ruff check src/cybersec_slm/ingestion/common.py src/cybersec_slm/ingestion/crawl_runner.py src/cybersec_slm/ingestion/scrape_html.py`
Expected: no new errors (fix any E501/line-length in the new code).

- [ ] **Step 3: Confirm the old crawler internals are gone**

Run: `uv run python -c "import cybersec_slm.ingestion.scrape_html as s; assert not hasattr(s, '_render_js') and not hasattr(s, '_robots_checker'); print('BFS internals removed')"`
Expected: prints "BFS internals removed".

- [ ] **Step 4: Commit any fixes**

```bash
git add -A
git commit -m "test: regression fixes after scrapy + polars ingestion changes"
```

---

## Self-Review

**Spec coverage:**
- Scrapy engine swap, per-source subprocess, unchanged `crawl()` seam -> Task 4.
- Standalone runner with fresh reactor -> Task 3.
- scrapy-playwright routed by `use_js`, lazy -> Task 3 `build_settings` (handlers set only when `use_js`).
- Fail-the-source on error, BFS crawler removed -> Task 4 (`_record_failed`; full rewrite drops internals; Task 5 Step 3 asserts removal).
- Double timeout bound (CLOSESPIDER_TIMEOUT + subprocess timeout) -> Task 3 settings + Task 4 `subprocess.run(timeout=...)`.
- Polars fast path for large csv/parquet/jsonl with provenance parity -> Task 2 (`_polars_enrich`, `_polars_to_jsonl`).
- pandas fallback on failure/exotic formats -> Task 2 Step 5 (`try/except`).
- Cap enforcement on polars output -> Task 2 (`_polars_to_jsonl` cap branch, tested).
- Core deps added -> Task 1.
- Tests: spider extraction (Task 3), local-server crawl (Task 3), subprocess failure (Task 4), polars parity/fallback/cap (Task 2) -> covered.

**Placeholder scan:** No TBD/TODO; every code step shows full code.

**Type consistency:** `crawl()` signature identical across Task 4 and worker.py. `_polars_to_jsonl(original, jsonl, cap, meta)` and `_polars_enrich(lf, meta)` names match between definition (Task 2 Step 4) and tests/usage (Task 2 Steps 1, 5). `extract`, `SiteSpider`, `build_settings`, `main` names match between Task 3 module and its tests. `BIG_FILE_BYTES` used consistently after the rename.
