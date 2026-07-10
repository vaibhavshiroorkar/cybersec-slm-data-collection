# Scrapy crawler engine swap + polars big-file conversion

Date: 2026-07-11
Status: Approved (design)
Scope: ingestion stage only

## Summary

Two independent ingestion upgrades, shipped together:

1. **Scrapy crawler.** Replace the hand-rolled BFS crawler behind the `website`
   source kind with Scrapy, run as an isolated subprocess per site. The public
   `crawl()` seam and every downstream contract (light-EDA gate, per-source
   timeout, resume ledger, inline cleaning, `Sources.csv`) stay unchanged.
2. **Polars big-file conversion.** Add a polars lazy `scan_* -> sink_ndjson`
   fast path for large `.csv` / `.parquet` / `.jsonl` files in `to_jsonl`.
   pandas remains the fallback for small files and exotic formats. Polars is a
   performance fast path, never a correctness dependency.

## Motivation

- 28 of 192 catalog sources are `website` kind (15%), a meaningful path. The
  current crawler ([scrape_html.py](../../../src/cybersec_slm/ingestion/scrape_html.py))
  is sequential (one page, then `sleep(0.3)`) with no retry/backoff or
  autothrottle. Scrapy gives per-domain concurrency, autothrottle, retry, and a
  dupefilter for the crawl path.
- Large CSV/parquet/jsonl sources (catalog sizes reach 10.8 GB) dominate
  conversion time. The current big-CSV path streams row-by-row via orjson;
  polars lazy scan + `sink_ndjson` converts at constant memory and is markedly
  faster.

## Constraints that shaped the design

- Ingestion runs **one source per process** in a `ProcessPoolExecutor`
  ([parallel.py](../../../src/cybersec_slm/ingestion/parallel.py)), each with a
  light-EDA gate, per-source wall-clock timeout, resume ledger, and inline
  cleaning in the parent.
- Scrapy owns a **Twisted reactor** that runs once per process and resists being
  embedded inside another concurrency framework's workers. Running it as a
  **fresh subprocess** gives it a clean reactor and sidesteps the conflict.
- 0 of the 28 current `website` sources set `use_js`, so the Playwright path is
  wired but latent. It must not burden static crawls or machines without
  chromium.

## Design decisions (locked)

| Decision | Choice |
|---|---|
| Scrapy integration | Engine swap, per-source, via subprocess |
| JS rendering | `scrapy-playwright` (routed by the `use_js` flag), lazy-loaded |
| Crawl failure | Fail the source; remove the old BFS crawler. Pool retry + timeout cover transients |
| Polars scope | Ingestion big-file conversion only; pandas untouched elsewhere |
| Dependencies | `scrapy`, `scrapy-playwright`, `polars` as core deps |

## Part 1 - Scrapy crawler

### Components

**`ingestion/crawl_runner.py` (new).** A `python -m cybersec_slm.ingestion.crawl_runner`
entry point. Imports only Scrapy (no pipeline code) so it starts fast in a fresh
reactor process. Responsibilities:

- Parse the site config from argv/JSON: `start_url`, `allow_prefix`, `max_pages`,
  `use_js`, `out_path`, `user_agent`, `download_delay`, `close_timeout`,
  `license`, `description`.
- Define a same-domain `Spider`:
  - `allowed_domains` = host of `start_url`.
  - Follow links via a `LinkExtractor` restricted to `allow_prefix`, same host.
  - Extract `title` + body text with nav/footer/header/script/style/svg/noscript/form
    stripped (parity with the current `_extract`); emit an item
    `{source, url, license, text}` only when `len(text) > 200`.
  - Playwright download handler enabled **only** when `use_js`, imported lazily.
- Build settings: `ROBOTSTXT_OBEY=True`, `CLOSESPIDER_PAGECOUNT=max_pages`,
  `CLOSESPIDER_TIMEOUT=close_timeout`, `DOWNLOAD_DELAY` + `AUTOTHROTTLE_ENABLED`,
  conservative `CONCURRENT_REQUESTS_PER_DOMAIN`, `USER_AGENT` = `common.HEADERS`
  UA, `FEEDS = {out_path: {format: jsonlines}}`, `LOG_LEVEL=WARNING`.
- Run `CrawlerProcess(settings).crawl(spider); .start()`.

**`ingestion/scrape_html.py` (reshaped).** Keeps the public function
`crawl(domain, slug, start_url, lic, use_js, max_pages, allow_prefix, desc, log)`
so [worker.py](../../../src/cybersec_slm/ingestion/worker.py) is unchanged. New body:

- Compute `out = data/raw/<domain>/<slug>/<slug>.jsonl`; ensure folder.
- `subprocess.run([sys.executable, "-m", "cybersec_slm.ingestion.crawl_runner", ...],
  timeout=close_timeout + buffer)`.
- On success with a non-empty JSONL: write `_SOURCE.json`, count rows + size,
  `log.record(... status="ok")` exactly as today.
- On non-zero exit / `TimeoutExpired` / empty or absent JSONL:
  `log.record(... status="failed...")` and return. No exception escapes.
- The BFS/robots/`_render_js`/`_get_html` internals are deleted.

### Data flow (unchanged downstream)

catalog row (`website`) -> descriptor -> `worker.process_source` ->
`scrape_html.crawl()` -> **subprocess Scrapy spider** ->
`data/raw/<domain>/<slug>/<slug>.jsonl` + `_SOURCE.json` -> ingest-log record ->
light-EDA gate -> inline clean. Record schema and folder shape are identical, so
nothing after the crawl changes.

### Error handling and timeouts

A hung crawl is bounded twice: Scrapy `CLOSESPIDER_TIMEOUT` inside the child, and
`subprocess.run(timeout=...)` set below the pool's per-source budget so the child
self-terminates rather than orphaning when the pool force-shuts-down on timeout.
Transient failures are resubmitted by the pool (`MAX_SOURCE_RETRIES`); persistent
failures mark the source failed and are logged. No fallback crawler.

## Part 2 - Polars big-file conversion

### Behavior

In `to_jsonl` ([common.py](../../../src/cybersec_slm/ingestion/common.py)):

- Rename `BIG_CSV_BYTES` -> `BIG_FILE_BYTES` (keep the 200 MB value) so the
  threshold applies to csv/parquet/jsonl.
- For a large `.csv` / `.parquet` / `.jsonl`, call `_polars_to_jsonl`:
  - Lazy scan: `pl.scan_csv(..., ignore_errors=True)` / `pl.scan_parquet` /
    `pl.scan_ndjson`.
  - `_polars_enrich(lf, meta)`: add `source/url/license` literal columns when
    absent; derive `text` via `coalesce` over the same candidate columns as
    `enrich_df` (`text, content, body, description, ...`) and the Q&A pair
    concatenation, all lazily.
  - `sink_ndjson(out)` (streaming, constant memory).
  - After sink, if output > `CAP_BYTES`: remove it and return `cap + 1`
    (matches the existing streamer contract).
- Fallback: if polars import fails or a scan raises, fall through to the current
  pandas `read_any` / orjson streamer. Small files and exotic formats (xlsx,
  ragged txt, json-repair, YARA) always use pandas.

### Provenance parity

`_polars_enrich` must produce the same `source`, `url`, `license`, and `text`
fields that `enrich_df` produces for the pandas path, so the cleaning stage finds
required provenance on every record regardless of which engine converted the file.

## Dependencies

Add to core deps in [pyproject.toml](../../../pyproject.toml):

- `scrapy>=2.11`
- `scrapy-playwright>=0.0.40` (Playwright + chromium already shipped)
- `polars>=1.0`

## Testing

Scrapy:
- Spider extraction: parse a fixture HTML offline; assert title/body/link parity
  with the old `_extract` and the 200-char filter.
- `crawl()`: serve 2-3 linked pages from a local `http.server`; run a real crawl;
  assert JSONL records + ingest-log row + `_SOURCE.json`. No network.
- Failure path: force a non-zero subprocess exit; assert `status="failed"` and no
  pool crash.
- Existing worker / light-EDA / resume tests stay green.

Polars:
- Parity: convert the same csv/parquet/jsonl through polars and pandas; assert
  identical rows + provenance + `text`.
- Fallback: malformed input falls back to pandas without error.
- Cap: output exceeding `CAP_BYTES` is removed and signaled.

## Out of scope

- Polars in EDA or anywhere outside `to_jsonl`.
- Any change to non-`website` fetch handlers.
- A fallback crawler for failed Scrapy crawls.
- Exercising `use_js` (no current catalog source needs it; the path is wired and
  ready).

## Rollback

Each part is independent. Reverting the Scrapy commit restores the BFS crawler;
reverting the polars commit restores the orjson/pandas conversion path. Neither
change alters record schema, folder layout, or the catalog, so a corpus built
before or after is byte-compatible downstream.
