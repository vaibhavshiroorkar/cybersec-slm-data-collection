# Dashboard: pipeline monitor + dataset explorer

**Status:** approved design · **Date:** 2026-07-02

## Context

`cybersec-slm` is a CLI-driven pipeline that builds a cybersecurity SLM training
corpus (sourcing → ingestion → cleaning → EDA gate → normalization →
`data/final/dataset.jsonl` + `manifest.json`). It has no frontend; all insight
comes from reading files under `data/` and `logs/`.

We want a **local-first, read-only web dashboard** that does two jobs:

1. **Monitor the pipeline** — live during a run *and* historical review of past
   runs (EDA sufficiency gate, source table, stage reports, manifest).
2. **Explore the dataset** — search/filter/browse the final corpus, and see what
   was rejected/deduplicated.

Decisions locked during brainstorming:
- **Stack:** Streamlit (pure Python; no JS toolchain; purpose-built for data apps).
- **Deployment:** local now, hosted-ready. The hosted seam is the existing
  `CYBERSEC_SLM_DATA_ROOT` resolution in `core.py` — point the root at a synced/
  mounted location and the same UI + read layer serve a hosted deploy unchanged.
- **Read-only.** No triggering runs, no auth, no annotation/source editing (those
  were other frontend directions we did not pick).

## Architecture

A new self-contained package with a hard split between reading and rendering:

```
src/cybersec_slm/dashboard/
  __init__.py
  data.py          # THE read layer. Only code that touches disk/SQLite.
                   # Pure functions -> plain dict/list. No Streamlit import.
                   # Resolves paths via core.data_root() (fresh env read), so it
                   # is unit-testable against a tmp data-root and hosted-ready.
  charts.py        # small format/trend helpers (no Streamlit-specific state)
  app.py           # Streamlit entrypoint: page config + landing/overview
  pages/
    1_Pipeline.py  # monitor: live strip + EDA gate + trends + source/report/manifest
    2_Dataset.py   # explore: filter/search/paginate corpus + "what didn't make it"
  README.md
```

- **Optional dependency group** `dashboard = ["streamlit>=1.40"]` in
  `pyproject.toml` (mirrors `orchestration` / `profiling`); plain `uv sync` stays
  lean, `uv sync --extra dashboard` pulls it in. Streamlit bundles Altair, so
  charts need no extra dependency.
- **CLI subcommand** `cybersec-slm dashboard [--port N]` in `cli.py` shells out to
  `streamlit run .../app.py` (via `sys.executable -m streamlit`), with a helpful
  message if the extra isn't installed (like the `flow` subcommand's degradation).
- **Path resolution:** `data.py` derives all paths from `core.data_root()` each
  call (which reads `CYBERSEC_SLM_DATA_ROOT` fresh), NOT the frozen `core.DATA_ROOT`
  constant — this is what makes it testable and hosted-ready.

## The read layer (`data.py`)

Every function tolerates missing artifacts (fresh checkout / run not yet complete)
by returning empty/None rather than raising. Representative API:

- `run_status()` → `{state: "running"|"idle", newest_log, mtime, elapsed}` — a run
  is "running" if a `logs/pipeline.<pid>.log` was modified within a short window.
- `live_progress()` → `{completed, total, log_tail}` — `completed` = line count of
  `logs/completed_sources.txt`; `total` = approved-source count from the catalog +
  allowlist; plus the tail of the newest per-PID log.
- `latest_eda()` → parsed `logs/eda/latest.json` (gate status, blockers, warnings,
  metrics).
- `eda_history()` → time-ordered list from `logs/eda/run-*.json` for trend charts.
- `source_table()` → rows from `logs/final_table.csv` (fallback: `ingest_log.sqlite`).
- `clean_report()` / `normalize_report()` → `logs/clean_report.csv` totals /
  `logs/normalize_report.json`.
- `manifest()` → `data/final/manifest.json`.
- `dataset_facets()` → filter values + counts (domain/subdomain/source/type/lang),
  sourced from `manifest.json` when present (cheap), else scanned.
- `dataset_page(filters, search, offset, limit)` → streams `dataset.jsonl` via
  `core.iter_jsonl`, applies filters + case-insensitive substring search on `text`,
  returns `(rows, match_count, capped)`. Never loads the whole file; match count is
  capped ("first N matches") to bound work. Cached per query by the page via
  `st.cache_data`. Implementation may later swap to DuckDB behind this same
  signature with no UI change.
- `sidecar(kind, limit)` → preview of `rejected.jsonl` / `duplicates.jsonl` /
  `dedup_scores.jsonl`.

## Pages (presentation only — all reads via `data.py`)

**`app.py`** — landing: title, resolved data root, one-line run status, and links
to the two pages (Streamlit auto-lists `pages/` in the sidebar).

**`1_Pipeline.py`** — top-to-bottom:
- **Live strip** (only when `run_status()=="running"`): `completed/total`, log tail,
  elapsed; wrapped in `@st.fragment(run_every=3)` so only this strip re-runs every
  ~3s. Idle → a manual "refresh" button (no busy-loop).
- **EDA gate:** latest pass/fail, blockers (error), warnings (warn), metric row.
- **Trends:** Altair line charts over `eda_history()` (total records, drift, dup%).
- **Sources table:** sortable/filterable `st.dataframe`.
- **Stage reports + manifest:** clean/normalize totals; manifest counts + git sha.

Nuance (documented in-page): the ingest-log SQLite is written at run end, so the
Sources table + stage reports populate once a run finishes; the live strip covers
the in-flight view via `completed_sources.txt` + log tail.

**`2_Dataset.py`**:
- Filter dropdowns (from `dataset_facets()`) + a text search box.
- Paginated results table (id, source, subdomain, type, tokens, lang, snippet) with
  prev/next; row selection opens a full 22-field record detail.
- "What didn't make it": previews of rejected/duplicates/dedup-scores sidecars.

## Testing

- `tests/dashboard/test_data.py` — headless, no Streamlit. Seeds a `tmp_path`
  data-root (fake `logs/eda/latest.json` + `run-*.json`, `final_table.csv`,
  `normalize_report.json`, `manifest.json`, `completed_sources.txt`, a few-line
  `dataset.jsonl`) via `CYBERSEC_SLM_DATA_ROOT`, then asserts: EDA parse + gate
  status, history ordering, source-table shape, `dataset_page` filter/search/
  pagination + cap, `live_progress` counting, and graceful empties on a bare root.
- `tests/dashboard/test_app_smoke.py` — `pytest.importorskip("streamlit")` +
  `streamlit.testing.v1.AppTest` runs each page against a seeded root and asserts no
  exception. Skips cleanly when the extra isn't installed, so default `uv sync`
  test runs stay green.

## Non-goals (v1, deliberate YAGNI)

Triggering/stopping runs; auth/multi-user; annotation or allowlist/source editing;
DuckDB indexing (only if scan speed becomes a problem — the `dataset_page` seam
allows it later without UI change).

## Verification

`uv sync --extra dashboard`; `uv run pytest tests/dashboard -q`; headless boot smoke
(`streamlit run ... --server.headless true`, confirm it serves, then stop);
`cybersec-slm dashboard --help`.
