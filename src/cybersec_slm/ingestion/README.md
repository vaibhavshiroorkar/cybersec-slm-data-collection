# Ingestion

Scripts that pull cybersecurity text data from each source and normalize it to
JSONL under `data/raw/`. Provenance for every produced/skipped file is recorded
in a SQLite ingest log under `logs/`.

## Modules
| File | Purpose |
|---|---|
| `common.py` | Ingestion helpers: HTTP (httpx + tenacity), robust readers (pandas + json-repair), JSONL conversion, and the SQLite `IngestLog`. Shared logger/paths/hashing come from `cybersec_slm.core`. |
| `sources.py` | Reads the curated catalog (`sources/Sources.csv`) and maps each row to a source descriptor (kind: hf/kaggle/github/url/pdf/feed/website/api/xml). |
| `allowlist.py` | The fetch gate: only sources `approved` in `sources/allowlist.yaml` are pulled. |
| `fetch.py` | Dataset fetcher, one handler per kind (hf, kaggle, github, url). |
| `scrape.py` | PDFs (PyMuPDF, one record per page) and JSON feeds (httpx + orjson). |
| `scrape_html.py` | Crawls robots.txt-permitted sites (selectolax; Playwright for JS pages). |
| `fetch_nvd.py` | The NVD CVE 2.0 paginated API handler. |
| `parallel.py` / `worker.py` | Per-source process isolation for the streaming run. |
| `run.py` | Final-table reporter for the ingest log (`show_table()`). |

## Paths
Resolved by `cybersec_slm.core` from `CYBERSEC_SLM_DATA_ROOT` (default: current
directory):

- raw data  → `data/raw/<Sub-Domain>/<source>/*.jsonl`
- logs      → `logs/pipeline.log`
- ingest db → `logs/ingest_log.sqlite`
- table     → `logs/final_table.csv`

## Usage
Ingestion is not a standalone command, it runs fused with cleaning, one process
per source, via the streaming path:

```bash
cybersec-slm run    # parallel per-source fetch + clean -> data/clean/
cybersec-slm all    # run + EDA gate + normalize (full pipeline)
```

Sources come from `sources/Sources.csv` (see `sources.py`); only rows `approved`
in `sources/allowlist.yaml` are fetched.

## Notes
- A 5 GB cap (`common.CAP_BYTES`) guards both downloads and produced JSONL;
  oversized files are skipped but still recorded in the log.
- Kaggle sources need credentials (`~/.kaggle/kaggle.json` or the
  `KAGGLE_USERNAME` / `KAGGLE_KEY` environment variables).
- `scrape_html.py`'s JS path needs the Playwright browser: `playwright install chromium`.
- Record schema produced by scrapers: `{source, url, license, page?, text}`.
