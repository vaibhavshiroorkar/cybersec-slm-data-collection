# Overlapped Ingest + Sequential Clean — Design

**Date:** 2026-07-09
**Status:** Approved for planning
**Area:** `src/cybersec_slm/ingestion/`, `src/cybersec_slm/cleaning/`, `src/cybersec_slm/orchestration/`

## Problem

The uncommitted v1→v2 refactor split the build into four strictly sequential
phases. `run_v2_pipeline` runs `run_parallel_ingest` (parallel fetch + light-EDA,
**no cleaning**) to full completion, and only then calls `run_aggregated_clean`.
Consequences the operator is hitting:

1. **Cleaning never overlaps fetching.** Wall-clock is `fetch_time + clean_time`.
   In v1 each worker cleaned its own source, so cleaning overlapped fetching;
   the v2 refactor removed that (`worker.process_source` no longer cleans).
2. **The run can get stuck.** The `parallel.py` path (used by `run` / `all`) has
   **no per-source timeout**. `as_completed` blocks forever on a hung worker
   (`HfApi().dataset_info`, Kaggle auth, a slow-drip HTTP stream). Only the
   Prefect path has `timeout_seconds`.
3. **The run is slow on failures.** The 3× retry loop rebuilds the *entire*
   process pool and re-runs every still-failed source with no backoff, and the
   "retrying … with troubleshooting" log is a lie — nothing changes between
   attempts, so a deterministically-failing source burns 3× its time.
4. **Latent bugs.** A no-op `for … in find_input_files(RAW_DATA): pass` scan of
   the whole raw tree before `rmtree`; `ingest_rows` dropped on the crash path;
   sources that fail mid-fetch leave partial JSONL that the aggregated pass then
   cleans into the corpus.

## Goal

Clean **sequentially in the parent** while fetching **in parallel** in worker
processes, keep dedup **deterministic/reproducible**, and make a single hung or
failing source unable to stall or badly slow the run.

## Decisions (locked)

- **Cleaning architecture:** inline parent cleaner + deterministic final dedup
  pass. Per-source cleaning during the live pass runs with the deduper
  **disabled**; one sorted global dedup pass runs at the end.
- **Robustness:** per-source wall-clock timeout + capped retries.
- **Fresh-run hygiene:** a fresh (non-`--resume`) run wipes `data/clean/` and
  `data/raw/` at the start so stale outputs from catalog sources that no longer
  exist cannot linger. `--resume` leaves both trees intact.

## Architecture

Replace the phase-1 → phase-2 split with a **single overlapped stage**: a pool of
worker processes fetches sources in parallel (producer); the parent process
consumes each finished source and cleans it inline, one source at a time
(sequential consumer). Then a deterministic global dedup pass, then EDA, then
normalize.

```
run_ingest_clean(spec, *, workers, resume, keep_raw, limit, source_timeout):
    setup:
        resolve descriptors; on --resume, drop those already in the ledger
        on a fresh run: reset ledger + dedup state; wipe data/clean + data/raw
        build Redactor / LangFilter / Translator ONCE in the parent
        deduper = Deduper(enabled=False)          # global dedup deferred to the final pass
    fetch + clean loop:
        pool  = ProcessPoolExecutor(workers, mp_context=spawn)   # workers fetch + light-EDA only
        submit worker.process_source(d) for every descriptor
        while pending futures remain:
            done, _ = wait(pending, timeout=POLL, return_when=FIRST_COMPLETED)
            for fut in done:
                meta = fut.result()               # BrokenProcessPool -> rebuild (see Robustness)
                record ingest_rows / flags / light_eda_report
                if status == "ok":
                    clean_source_folder(meta.folder) -> data/clean/   # deduper disabled, shared transformers
                    delete data/raw/<source>/ unless keep_raw
                    ledger.write(descriptor_key(d))
                elif status in ("skipped", "rejected"):
                    record; ledger only for "skipped"; no clean
                else  # "failed"
                    resubmit once (capped) or mark failed
            timeout sweep over still-running futures (see Robustness)
        force pool shutdown
    return summary(ok, failed, skipped, rejected, timed_out, ingest_rows, light_eda_reports, flags)

run_v2_pipeline:
    run_ingest_clean(...)
    final_global_dedup(data/clean, resume=resume)   # sorted, deterministic, resumable
    deep EDA gate  ->  normalize
```

### Why sequential-clean-in-parent (not v1's clean-in-worker)

The heavy cleaning models — Presidio+spaCy (`Redactor`) and fastText
(`LangFilter`) — cost seconds and hundreds of MB to build. v1 built them **once
per worker** (N× memory + N× startup). Cleaning in the parent builds them
**once**. Cleaning is single-threaded but overlaps the network-bound fetch, so
wall-clock ≈ `max(fetch, clean)` instead of `fetch + clean`. If cleaning is
slower than fetching, raw folders accumulate on disk (bounded by corpus size)
and cleaning finishes as a short tail after fetch — still ≤ the current
two-phase wall-clock.

## Dedup model (reproducible)

Per-source inline cleaning uses `Deduper(enabled=False)`, so which of two
cross-source duplicates survives cannot depend on fetch-completion order. After
the pool drains, `final_global_dedup(data/clean, resume=…)` runs one **sorted,
deterministic** cross-source pass (files processed in sorted `rel` order →
stable "first-wins"). This is the existing function; it is already crash-
resumable via `DEDUP_CKPT` / `DEDUP_DONE`. Dedup semantics are unchanged; the
pass simply no longer sits idle behind fetching.

## Robustness

### Per-source wall-clock timeout
- `source_timeout` defaults to **1800 s (30 min)**, configurable via a new
  `--source-timeout` CLI flag and an env var. The parent records each future's
  start time.
- A source exceeding its budget is recorded **failed (timed-out)** and **not
  retried** — a 30-minute hang almost always repeats and is expensive.

### A hang must not stall the run
- `ProcessPoolExecutor` cannot kill a single worker without going `Broken`, so on
  a timeout the parent **tears the pool down** (terminates workers), then
  **rebuilds a fresh pool and resubmits the still-unfinished, non-timed-out
  siblings**. Sources already cleaned are in the ledger and are skipped on
  resubmit, so only genuinely in-flight siblings restart. The hung source is
  marked failed and never resubmitted, so it costs at most one timeout budget.
- Total pool rebuilds are bounded (`MAX_POOL_REBUILDS = 2`) so a pathological
  source cannot cause infinite restarts; once exhausted, any remaining
  unfinished sources are marked failed and the stage proceeds.

### Capped per-source retries
- A source that *raises* (transient network/parse error) is resubmitted **once**
  into the pool; the HTTP layer (`common.http_get` / `download`) already backs
  off via tenacity (4 attempts, exponential).
- `BrokenProcessPool` follows the same bounded rebuild-and-resubmit path as a
  timeout.

### Wait granularity
- `POLL ≈ 10 s`. While the parent is synchronously cleaning a source it is not
  polling, so timeout detection lags by at most one source's cleaning time —
  negligible against a 30-minute budget.

## Bug fixes bundled in

- **O(n²) raw rescan:** `clean_one_source` scans `find_input_files(RAW_DATA)`
  (the whole tree) and filters to one folder — quadratic across a run. Replace
  with a helper that scans the finished source's folder directly, keeping `rel`
  relative to `data/raw/` so the `data/clean/` layout is preserved.
- **Partial-data cleaning:** only `status == "ok"` sources (light-EDA passed) are
  cleaned, so a source that failed mid-fetch never has partial JSONL swept into
  the corpus.
- **Retry accounting + honest logs:** collect `ingest_rows` on the crash path;
  remove the misleading "retrying … with troubleshooting" message.
- **Dead code:** delete the no-op pre-`rmtree` scan (raw is now deleted
  per-source inline).
- **`worker.process_source`:** drop the now-unused `keep_raw` / `limit` params.

## Components & interfaces

- `ingestion/parallel.py`
  - `run_ingest_clean(spec, *, workers, resume, keep_raw, limit, source_timeout) -> dict`
    — new fused producer/consumer stage (replaces `run_parallel_ingest` +
    `run_aggregated_clean`).
  - `run_v2_pipeline(...)` — calls `run_ingest_clean` → `final_global_dedup` →
    `run_deep_eda` → `run_normalize`; gains a `source_timeout` param.
  - `run_aggregated_clean` / `run_parallel_ingest` removed (or the latter kept as
    a thin wrapper only if a test needs fetch-only; default is to remove).
- `cleaning/pipeline.py`
  - `clean_source_folder(folder, *, redactor, langf, translator, raw_root, clean_data_dir, limit) -> list[dict]`
    — clean one already-fetched source folder with a **disabled** deduper and
    caller-supplied transformers; `rel` computed relative to `raw_root`. Fixes
    the O(n²) rescan. `clean_one_source` is refactored onto it or removed.
- `ingestion/worker.py` — `process_source` loses `keep_raw` / `limit`.
- `cli.py` — add `--source-timeout` to `run` and `all`; thread it through.
- `orchestration/flows.py` — keep consistent: fetch `.map` → a single sequential
  clean task (disabled per-source deduper) → `final_global_dedup` → EDA →
  normalize. The CLI is the overlap-optimized path; the Prefect flow stays
  correct but is not required to overlap.

## Data flow

```
descriptors ──parallel──> worker.process_source (fetch + light-EDA)
                              │ status=ok, folder
                              ▼
             parent: clean_source_folder (dedup OFF) ──> data/clean/<domain>/<source>/
                              │
                              ▼ (unless --keep-raw)
                        delete data/raw/<source>/  + ledger append
   ... pool drains ...
data/clean ──> final_global_dedup (sorted, dedup ON) ──> data/clean (rewritten in place)
           ──> deep EDA gate ──> normalize ──> data/final/dataset.jsonl
```

## Error handling

| Situation | Handling |
|---|---|
| Source raises (network/parse) | resubmit once; then mark failed |
| Source exceeds `source_timeout` | mark failed (timed-out); rebuild pool, resubmit siblings; never resubmit the hung source |
| `BrokenProcessPool` | bounded rebuild + resubmit remaining |
| Light-EDA rejects source | worker moves raw → `data/dropped/_rejected/`; parent records, no clean |
| License-gated source | worker returns `skipped`; parent records + ledgers; no fetch/clean |
| Crash mid-run | ledger + dedup checkpoint make `--resume` restart where it stopped |

## Testing (TDD)

1. **Overlap parity** — overlapped run produces the same `data/clean/` tree and
   report totals as the old two-phase run for a small fixture catalog.
2. **Timeout** — a worker that sleeps past `source_timeout` is marked failed
   (timed-out) and the run still completes and cleans the other sources.
3. **Resume** — a run interrupted after some sources are cleaned skips the
   ledgered sources on `--resume` and finishes the final dedup pass; no source is
   fetched twice.
4. **Deterministic dedup** — two runs over the same fixtures produce identical
   surviving records (final pass is order-independent).
5. **O(files) cleaning** — `clean_source_folder` reads only its own folder (guard
   against reintroducing the whole-tree scan).
6. Update `tests/ingestion/test_parallel_resume.py` for the fused entry point.

## Out of scope

EDA phase-3 logic and normalize (verified: auto-rebalance runs once, no loop),
catalog/sourcing, dashboard.
