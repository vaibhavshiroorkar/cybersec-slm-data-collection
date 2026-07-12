# Five-Stage Pipeline + Dashboard Rework

Date: 2026-07-12
Status: Design (awaiting review)

## Motivation

The pipeline currently fuses ingest and clean into one overlapped phase
(`run_ingest_clean`) and treats cross-source dedup as its own phase. The mental
model the project wants is five clean, independent steps:

1. **Sourcing** - discover / curate sources into `sources/Sources.csv`
2. **Ingest** - fetch raw data from those sources
3. **Clean** - clean records (per-source clean + cross-source dedup)
4. **EDA** - the sufficiency gate
5. **Schema** - normalize to the canonical schema and release the dataset

Today the truth about "what are the stages" is scattered across three
disconnected places: the CLI subcommands, the `_PHASE_DEFS` log-marker parser in
`dashboard/data.py`, and ad-hoc `logger.info("phase N ...")` strings. This rework
makes the five-stage model the single canonical shape of the code, then rebuilds
the Streamlit dashboard to follow it (a page per stage), with a stable,
non-jumping layout and scrollable logs.

The work splits into two sub-projects. B depends on A.

- **A. Pipeline restructure** (backend): canonical stage registry, physically
  separated ingest and clean, per-stage CLI and control.
- **B. Dashboard rework** (frontend): overview of all stats plus one page per
  stage, stable layout, scrollable logs, advanced run settings, per-stage run
  controls.

## Decisions (locked)

- **Execution model:** physically separate. The full run is
  `ingest ALL -> clean ALL -> eda -> schema`, no I/O<->CPU overlap. Each stage is
  an independent, resumable pass.
- **Dedup:** folds into Clean. Cross-source dedup (`final_global_dedup`) is the
  final aggregation step of the Clean stage. The standalone "dedup" phase is gone.
- **Raw disposal:** Clean deletes `data/raw/` after cleaning by default (disk
  stays bounded); `--keep-raw` retains it. Re-running Clean after a delete
  requires a re-ingest.
- **Overlapped path:** removed. The old `run` / `run_ingest_clean` combined
  function is deleted so there is exactly one execution model. Its process-pool
  orchestration is refactored into a reusable fetch-only pass, not discarded.
- **Per-stage re-run:** every stage page can run just its own stage, with
  stage-scoped advanced settings. `control.py` learns to launch individual stages,
  not only `all`.
- **CLI extension:** stage commands accept the relevant advanced flags, and `all`
  accepts the union.

## Sub-project A: the five-stage pipeline

### A1. Canonical stage registry (new `src/cybersec_slm/stages.py`)

A neutral top-level module in the package (not under `ingestion/`, since it
references cleaning, eda, and normalize too), importable by the CLI, `control.py`,
and the dashboard. One ordered definition is the single source of truth. Each
stage entry carries:

- `key` (e.g. `ingest`) and human `label`
- the CLI command that runs it
- input dir, output dir/artifact
- report artifact path(s)
- log-marker substrings used to detect the stage in a pipeline log

The CLI, the dashboard phase parser (replacing `_PHASE_DEFS`), and the dashboard
pages all read from this module.

| # | Stage    | Reads                    | Writes                                     | CLI         |
|---|----------|--------------------------|--------------------------------------------|-------------|
| 1 | `source` | `Sources.csv` (+ web)    | `Sources.csv`, `logs/discovered/`          | `source`    |
| 2 | `ingest` | `Sources.csv`            | `data/raw/`, `logs/ingest_log.sqlite`      | `ingest`    |
| 3 | `clean`  | `data/raw/`              | `data/clean/`, `logs/clean_report.csv`     | `clean`     |
| 4 | `eda`    | `data/clean/`            | `logs/eda/`                                | `eda`       |
| 5 | `schema` | `data/clean/`            | `data/final/dataset.jsonl` + `manifest.json` | `normalize` |

### A2. Execution changes (`ingestion/parallel.py`, `worker.py`, `cli.py`, `control.py`)

- **Ingest = fetch only.** Split `worker.process_source` into a `fetch_source`
  path that does fetch -> hazard/license (light-EDA) gate -> keep raw, stopping
  before clean. The existing process-pool machinery inside `run_ingest_clean`
  (submit / timeout / pool-rebuild / resume-ledger) is extracted into a reusable
  runner and driven with fetch-only work. Raw is retained. Resumable via
  `logs/completed_sources.txt` (skip already-fetched).
- **Clean = whole-tree pass.** Reuse the existing `clean_raw_tree` (per-source
  clean over `data/raw/`) and append `final_global_dedup` at the end. Delete
  `data/raw/` afterward unless `--keep-raw`.
- **`all`** runs the five stages in sequence with no overlap. The EDA gate can
  still halt the run (SufficiencyError) and report which stage stopped it.
- **Removed:** the combined `run_ingest_clean` and the `run` CLI subcommand.

### A3. CLI surface

- Add `ingest` (fetch all to raw).
- `clean` with no action runs the full Clean stage; the existing diagnostic
  actions (`sanitize|dedup|pii|lang|report|balance`) remain available under it.
- `normalize` gains a `schema` alias.
- Stage commands accept the flags they support: `--workers`, `--sources`,
  `--source-timeout`, `--limit`, `--keep-raw`, `--resume`, `--no-auto-rebalance`.
  `all` accepts the union (this adds `--workers` and `--sources` to `all`, which
  it lacks today).

### A4. Control plane (`dashboard/control.py`)

Generalize `start(resume=...)` into
`start(stage="all"|"source"|"ingest"|"clean"|"eda"|"schema", settings={...})`
that builds the correct `cybersec-slm <stage> ...` command with the advanced
flags. One control file still tracks that a run is active (only one stage runs at
a time). `stop()` and `reset()` are unchanged.

## Sub-project B: the dashboard rework

### B1. Navigation

Sidebar, ordered by filename:

```
Overview      app.py
1 Sourcing    pages/1_Sourcing.py
2 Ingest      pages/2_Ingest.py
3 Clean       pages/3_Clean.py
4 EDA         pages/4_EDA.py
5 Schema      pages/5_Schema.py
Dataset       pages/6_Dataset.py
Agent         pages/7_Agent.py
```

### B2. Overview page (all the stats, no reflow)

A fixed skeleton, top to bottom:

- Run-status strip: state, current stage, elapsed / ETA
- Five-chip stage strip: each stage shows done / running / pending / failed
- Funnel headline: Sources -> Ingested -> Cleaned -> Final (records + size)
- EDA gate summary: pass/fail + headline metrics
- Manifest headline: records, tokens, domains
- Full-pipeline launcher: Start / Resume / Stop / Reset + advanced settings

### B3. Stage page template (identical across the five stages)

1. Header: stage name + status pill + last-run time
2. Run control: `[Run this stage]` + advanced-settings expander (only that
   stage's flags) + `[Stop]` when live
3. Scrollable log box: `st.container(height=320)` so new lines scroll inside a
   fixed box instead of growing the page
4. Stage-specific detail, each in a fixed-height container:
   - Sourcing: catalog summary (total, by Sub-Domain) + discover control
   - Ingest: raw source count + size + per-source ingest ledger table
   - Clean: clean report (in/out, drop breakdown) + loss breakdown + dedup stats
   - EDA: sufficiency gate + metrics + trends + feedback
   - Schema: normalize report + manifest (by domain / by license)

### B4. Stable-layout technique (the "premium feel")

- Every auto-refresh region is a fixed-height `st.container(height=...)` or an
  `st.empty()` placeholder updated in place, so changing values never push
  content up or down.
- Consistent column grids (same metric count per row) so nothing shifts.
- Logs render in a scrollable container, never `st.code` (which reflows/grows).
- Collapse the current four independent `run_every` fragments into one
  coordinated refresh per page over a stable skeleton.

### B5. Shared modules

- New `dashboard/ui.py`: a small CSS injection plus helpers (`stage_header`,
  `stat_row`, `log_box`, `status_pill`, `section_card`) so every page is visually
  identical and each page file stays short.
- `dashboard/data.py`: add stage-keyed readers (`stage_status(key)`,
  `stage_log(key)`) that read the canonical registry from A1. Replace the
  hand-maintained `_PHASE_DEFS` with the registry.

## Delivery phases

- A1: stage registry
- A2: split ingest / clean, refactor the pool runner, update `all`
- A3: CLI commands + `control.py` per-stage launch
- A4: backend tests (ingest fetch-only, clean tree + dedup, `all` sequence,
  control command building), TDD for the execution split
- B1: `dashboard/ui.py` + Overview rebuild
- B2: the five stage pages from the shared template
- B3: wire per-stage run controls + advanced settings
- B4: stable-layout / scrollable-log pass
- B5: dashboard tests (stage readers, control command building) + manual run

## Testing

- Backend changes to execution are test-driven: ingest produces raw and records
  the ledger without cleaning; clean consumes raw, writes clean + report, runs
  dedup, and deletes raw unless `--keep-raw`; `all` runs the five stages in order
  and halts at the EDA gate on a blocker.
- `control.py` command building is unit-tested per stage (no real subprocess).
- Dashboard `data.py` stage readers are unit-tested against a temp data root, as
  the existing read-layer tests already are.
- Ruff + pytest must stay green (CI gates on both).

## Out of scope

- No change to the cleaning transforms themselves (PII, langfilter, translate,
  hazard scan) beyond how they are invoked per stage.
- No change to the sourcing/discovery logic beyond surfacing it as stage 1.
- No hosted/multi-user concerns; the dashboard stays local-first.

## Risks

- Physical separation retains the full raw corpus on disk until Clean runs, and
  loses the overlap speedup. Accepted deliberately.
- Splitting `process_source` touches the most intricate part of `parallel.py`
  (pool rebuild + timeout handling); this is why A2 is test-driven.
- Removing the `run` subcommand is a breaking CLI change; `ingest` + `clean` (or
  `all`) replace it, and the README/help text must be updated in the same change.
