# Five-Stage Pipeline Backend (Sub-project A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure the pipeline into five physically separate stages (source, ingest, clean, eda, schema), with a canonical stage registry, per-stage CLI commands, and per-stage dashboard control.

**Architecture:** Ingest becomes fetch-only (fetch to `data/raw/`, keep raw). Clean becomes a whole-tree pass plus cross-source dedup, deleting raw afterward. The intricate process-pool consume loop is extracted from `run_ingest_clean` into a reusable `_run_pool` runner that both ingest (and, if ever needed, other passes) can drive. `all` runs the five stages in sequence; the overlapped `run` path is removed.

**Tech Stack:** Python 3.13, `concurrent.futures.ProcessPoolExecutor` (spawn), pytest, ruff, uv.

## Global Constraints

- Ruff must pass: `uv run ruff check src tests` (CI gate). Line length <= 100.
- Tests must pass: `uv run pytest -q` (CI gate).
- No em dashes in comments, docs, or help text (project style).
- No Claude attribution in commit messages.
- Commit author stays the user's git identity (already configured).
- Windows-first dev shell is PowerShell; git is available via PowerShell, not the Bash tool.

---

## File structure

- Create `src/cybersec_slm/stages.py` — canonical five-stage registry + log-phase parser.
- Modify `src/cybersec_slm/ingestion/worker.py` — `process_source(..., clean=True)` gains a fetch-only mode.
- Modify `src/cybersec_slm/ingestion/parallel.py` — extract `_run_pool`; add `run_ingest`; add `run_clean`; rewrite `run_v2_pipeline`; delete `run_ingest_clean`.
- Modify `src/cybersec_slm/cli.py` — add `ingest`; make bare `clean` run the stage; `schema` alias for `normalize`; flags on `all`; remove `run`.
- Modify `src/cybersec_slm/dashboard/control.py` — `start(stage=..., settings=...)`.
- Modify `src/cybersec_slm/dashboard/data.py` — phase parser reads `stages.py`.
- Tests under `tests/ingestion/`, `tests/dashboard/`, `tests/` as noted per task.

---

## Task A1: Canonical stage registry

**Files:**
- Create: `src/cybersec_slm/stages.py`
- Test: `tests/test_stages.py`

**Interfaces:**
- Produces: `STAGES: list[Stage]` (ordered); `Stage` is a frozen dataclass with fields `key: str`, `label: str`, `cli: str`, `markers: tuple[str, ...]`. Helpers: `stage_keys() -> list[str]`, `get_stage(key: str) -> Stage`, `phase_from_log(lines: list[str]) -> str` returning a stage key or `"unknown"`/`"starting"`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_stages.py
from cybersec_slm import stages

def test_five_stages_in_order():
    assert stages.stage_keys() == ["source", "ingest", "clean", "eda", "schema"]

def test_get_stage_label_and_cli():
    s = stages.get_stage("ingest")
    assert s.label and s.cli == "ingest"

def test_phase_from_log_detects_clean_over_ingest():
    lines = ["ingest: fetched foo", "clean: in=10 out=8"]
    assert stages.phase_from_log(lines) == "clean"

def test_phase_from_log_unknown_when_empty():
    assert stages.phase_from_log([]) == "unknown"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_stages.py -q`
Expected: FAIL (module `stages` not found).

- [ ] **Step 3: Implement `stages.py`**

Define the `Stage` dataclass and `STAGES` list with keys `source, ingest, clean, eda, schema`, human labels, `cli` command names, and `markers` (log substrings that indicate a stage has been reached; reuse the substrings currently in `data._PHASE_DEFS` where they apply, e.g. clean markers `("clean:", "cleaned ", "final global dedup", "final dedup:")`, eda markers `("deep global EDA", "eda: scanning", "eda: total=")`, schema markers `("schema normalization", "normalize:", "provenance manifest")`, ingest markers `("ingest:", "fetched", "=== source:")`). `phase_from_log` scans lines and returns the furthest-along stage whose marker appears, else `"starting"` when lines exist but no marker matches, else `"unknown"`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_stages.py -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Ruff + commit**

Run: `uv run ruff check src/cybersec_slm/stages.py tests/test_stages.py`
```
git add src/cybersec_slm/stages.py tests/test_stages.py
git commit -m "feat(stages): canonical five-stage registry + log phase parser"
```

---

## Task A2: Fetch-only worker mode

**Files:**
- Modify: `src/cybersec_slm/ingestion/worker.py:84-143` (`process_source`)
- Test: `tests/ingestion/test_worker_fetch_only.py`

**Interfaces:**
- Consumes: existing `process_source(descriptor, *, data_root=None, limit=None)`.
- Produces: `process_source(descriptor, *, data_root=None, limit=None, clean=True)`. When `clean=False`, the worker fetches, runs the license + light-EDA gate, and returns with `clean_rows == []` and the raw folder left in place (never calls `clean_one_source`). A rejected source still moves to dropped; a licensed+passed source stays in `data/raw/`.

- [ ] **Step 1: Write the failing test**

Test that `process_source(descriptor, clean=False)` on a stub descriptor (monkeypatch `_fetch_one` to write a small jsonl into a temp raw folder, and `light_eda.assess_source` to pass) returns `status == "ok"`, `clean_rows == []`, and does NOT call `clean_one_source` (assert via a monkeypatched sentinel that raises if called).

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/ingestion/test_worker_fetch_only.py -q`
Expected: FAIL (`clean` is not a parameter / clean still runs).

- [ ] **Step 3: Implement the `clean` flag**

Add `clean: bool = True` to the signature. In the passed branch, guard the clean call: `if clean: result["clean_rows"] = clean_one_source(folder, limit=limit)`. Everything else unchanged.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/ingestion/test_worker_fetch_only.py -q`
Expected: PASS.

- [ ] **Step 5: Ruff + commit**

```
git add src/cybersec_slm/ingestion/worker.py tests/ingestion/test_worker_fetch_only.py
git commit -m "feat(worker): fetch-only mode (clean=False) for the ingest stage"
```

---

## Task A3: Extract the reusable pool runner

**Files:**
- Modify: `src/cybersec_slm/ingestion/parallel.py` (extract from `run_ingest_clean`, lines ~150-295)
- Test: `tests/ingestion/test_run_pool.py`

**Interfaces:**
- Produces: `_run_pool(descriptors, *, work_fn, on_result, workers, source_timeout, ledger) -> dict summary`. `work_fn(descriptor) -> future-returning callable` is what the pool submits (a picklable top-level callable + its kwargs); `on_result(descriptor, meta) -> bool` records one finished result and returns False for unknown/failed (so the runner applies retry). The runner owns: submit-up-to-`workers`, the `wait(FIRST_COMPLETED)` consume loop, the per-source timeout sweep, `BrokenProcessPool` handling, pool rebuilds (`MAX_POOL_REBUILDS`), retries (`MAX_SOURCE_RETRIES`), and draining unconsumed descriptors. It does NOT know about fetch vs clean.

- [ ] **Step 1: Write the failing test**

Drive `_run_pool` with a trivial in-process `work_fn` (submit a function returning `{"status": "ok"}` for each of 3 descriptors) and an `on_result` that counts. Assert all 3 are processed and the summary counts match. (Use a small real `ProcessPoolExecutor` with a module-level picklable function, or accept an injected executor factory as a test seam.)

- [ ] **Step 2: Run to verify fail**

Run: `uv run pytest tests/ingestion/test_run_pool.py -q`
Expected: FAIL (`_run_pool` not defined).

- [ ] **Step 3: Implement `_run_pool`**

Move the body of `run_ingest_clean` from pool creation through the finally/drain logic into `_run_pool`, parameterized by `work_fn` and `on_result`. Keep `run_ingest_clean` temporarily calling `_run_pool` so nothing else breaks yet (it is deleted in A6). Preserve the timeout sweep, rebuild loop, and the `pending_descriptors.extend(pending_iter)` drain fix.

- [ ] **Step 4: Run the full ingestion suite to verify no regression**

Run: `uv run pytest tests/ingestion -q`
Expected: PASS (existing resume/timeout/overlap tests still green).

- [ ] **Step 5: Ruff + commit**

```
git add src/cybersec_slm/ingestion/parallel.py tests/ingestion/test_run_pool.py
git commit -m "refactor(parallel): extract reusable _run_pool from run_ingest_clean"
```

---

## Task A4: `run_ingest` stage

**Files:**
- Modify: `src/cybersec_slm/ingestion/parallel.py`
- Test: `tests/ingestion/test_run_ingest.py`

**Interfaces:**
- Produces: `run_ingest(spec=None, *, workers=None, resume=False, limit=None, source_timeout=DEFAULT_SOURCE_TIMEOUT_S) -> dict`. Fetches all sources to `data/raw/` via `_run_pool` driving `worker.process_source(..., clean=False)`; writes the ingest log and the resume ledger; leaves `data/raw/` populated; writes NO `data/clean/`. Fresh (non-resume) wipes `data/raw/` first; resume skips completed keys.

- [ ] **Step 1: Write the failing test**

With a 2-row stub catalog and monkeypatched fetch (writes tiny jsonl into raw) + passing light-EDA, assert after `run_ingest`: `data/raw/` has both sources, `logs/ingest_log.sqlite` has ok rows, `data/clean/` is absent/empty, and `completed_sources.txt` lists both.

- [ ] **Step 2: Run to verify fail** — `uv run pytest tests/ingestion/test_run_ingest.py -q` → FAIL.

- [ ] **Step 3: Implement `run_ingest`**

Mirror `run_ingest_clean`'s setup (descriptor load, resume/reset, ledger, IngestLog), but drive `_run_pool` with `work_fn` = `process_source(clean=False)` and an `on_result` that records ingest rows + ledger but never cleans and never deletes raw. Log with `ingest:` prefixed markers so `stages.phase_from_log` classifies it.

- [ ] **Step 4: Run to verify pass** — `uv run pytest tests/ingestion/test_run_ingest.py -q` → PASS.

- [ ] **Step 5: Ruff + commit**

```
git add src/cybersec_slm/ingestion/parallel.py tests/ingestion/test_run_ingest.py
git commit -m "feat(parallel): run_ingest fetch-only stage"
```

---

## Task A5: `run_clean` stage

**Files:**
- Modify: `src/cybersec_slm/ingestion/parallel.py`
- Test: `tests/ingestion/test_run_clean.py`

**Interfaces:**
- Produces: `run_clean(*, keep_raw=False, limit=None, resume=False) -> dict`. Cleans the whole `data/raw/` tree (per-source via `cleaning.pipeline.clean_one_source` over each source folder, or `clean_raw_tree`'s pass) into `data/clean/`, writes `clean_report.csv`, then runs `final_global_dedup(resume=resume)`, then deletes `data/raw/` unless `keep_raw`. Returns `{"files","in","out","dedup": {...}}`.

- [ ] **Step 1: Write the failing test**

Seed `data/raw/<domain>/<source>/x.jsonl` with a few records (two identical across two sources to exercise dedup). Assert after `run_clean`: `data/clean/` populated, `clean_report.csv` present, `final_global_dedup` removed the cross-source duplicate, and `data/raw/` is gone (and present when `keep_raw=True`).

- [ ] **Step 2: Run to verify fail** — `uv run pytest tests/ingestion/test_run_clean.py -q` → FAIL.

- [ ] **Step 3: Implement `run_clean`**

Compose existing pieces: build the clean transformers once, iterate source folders under `data/raw/` calling `clean_one_source` (or reuse `clean_raw_tree` with `keep_raw=True` so raw survives for dedup), aggregate rows, `_write_report(rows)`, `final_global_dedup(resume=resume)`, then `_wipe_dir(core.RAW_DATA)` unless `keep_raw`. Log `clean:` markers.

- [ ] **Step 4: Run to verify pass** — `uv run pytest tests/ingestion/test_run_clean.py -q` → PASS.

- [ ] **Step 5: Ruff + commit**

```
git add src/cybersec_slm/ingestion/parallel.py tests/ingestion/test_run_clean.py
git commit -m "feat(parallel): run_clean whole-tree stage (clean + cross-source dedup)"
```

---

## Task A6: Rewire `run_v2_pipeline`, delete overlapped path

**Files:**
- Modify: `src/cybersec_slm/ingestion/parallel.py` (`run_v2_pipeline`; delete `run_ingest_clean`)
- Test: `tests/ingestion/test_ingest_clean_overlap.py` (repurpose/rename to `test_all_sequence.py`), plus adjust any test importing `run_ingest_clean`.

**Interfaces:**
- Produces: `run_v2_pipeline(spec=None, *, workers=None, resume=False, keep_raw=False, limit=None, source_timeout=..., enforce_eda=True, normalize=True) -> dict` now = `run_ingest -> run_clean -> run_deep_eda -> run_normalize` in sequence. `run_ingest_clean` no longer exists.

- [ ] **Step 1: Update/adjust tests**

Grep for `run_ingest_clean` across `tests/` and `src/` (e.g. `uv run python -c "import ..."` or ripgrep). Repoint the overlap test to assert the sequenced behavior (raw created by ingest, consumed by clean, then clean+eda+normalize outputs exist). Add an assertion that `data/raw/` is gone after a default `all`.

- [ ] **Step 2: Run to verify fail** — `uv run pytest tests/ingestion -q` → FAIL (old overlap expectations / missing symbol).

- [ ] **Step 3: Implement the rewire**

Rewrite `run_v2_pipeline` body to call `run_ingest(...)` then `run_clean(...)` then the existing `run_deep_eda` / `run_normalize`, preserving the SufficiencyError halt. Delete `run_ingest_clean`. Keep `clean_raw_tree` (still used by the Prefect flow).

- [ ] **Step 4: Run to verify pass** — `uv run pytest tests/ingestion -q` → PASS.

- [ ] **Step 5: Ruff + commit**

```
git add src/cybersec_slm/ingestion/parallel.py tests/ingestion
git commit -m "feat(parallel): all = ingest -> clean -> eda -> schema; drop overlapped path"
```

---

## Task A7: CLI surface (add `ingest`, reframe `clean`, `schema` alias, flags on `all`; remove `run`)

**Files:**
- Modify: `src/cybersec_slm/cli.py`
- Test: `tests/test_cli_stages.py`

**Interfaces:**
- Produces: `cybersec-slm ingest [--sources --workers --limit --resume --source-timeout]`; `cybersec-slm clean` (no action) runs `run_clean`, existing `clean <action>` diagnostics preserved; `cybersec-slm schema` aliases `normalize`; `all` accepts `--workers` and `--sources` in addition to today's flags; `run` subcommand removed.

- [ ] **Step 1: Write failing tests**

Parse-level tests (call `build_parser().parse_args([...])`): `ingest` accepts `--workers 4`; `all` accepts `--sources x.csv --workers 2`; `run` is rejected (SystemExit); `schema` resolves to the normalize handler. For `clean`, make the `action` positional optional (nargs="?") defaulting to the stage run.

- [ ] **Step 2: Run to verify fail** — `uv run pytest tests/test_cli_stages.py -q` → FAIL.

- [ ] **Step 3: Implement CLI changes**

Add the `ingest` subparser; make `clean`'s `action` optional and dispatch to `parallel.run_clean` when omitted; add `schema` as a second subparser mapping to the normalize handler (or `aliases=["schema"]`); add `--workers`/`--sources` to `all` and thread them into `run_v2_pipeline`; delete the `run` subparser and its handler branch. Update the module docstring usage block.

- [ ] **Step 4: Run to verify pass** — `uv run pytest tests/test_cli_stages.py -q` → PASS.

- [ ] **Step 5: Ruff + commit**

```
git add src/cybersec_slm/cli.py tests/test_cli_stages.py
git commit -m "feat(cli): per-stage commands (ingest/clean/schema); extend all; remove run"
```

---

## Task A8: Per-stage control plane

**Files:**
- Modify: `src/cybersec_slm/dashboard/control.py`
- Test: `tests/dashboard/test_control.py` (extend)

**Interfaces:**
- Produces: `start(stage: str = "all", *, resume: bool = False, settings: dict | None = None, _command=None) -> dict`. Builds `[python, -m, cybersec_slm, <stage>] + flags` from `settings` (workers, sources, source_timeout, limit, keep_raw, no_auto_rebalance) filtered to those the stage accepts. Backward compatible: `start(resume=True)` still launches `all --resume`. `stop`/`reset` unchanged.

- [ ] **Step 1: Write failing tests**

Assert the built command (via `_command` capture or a `build_command(stage, resume, settings)` helper) for: `all` + `{workers:4, source_timeout:600}` → contains `all --workers 4 --source-timeout 600`; `ingest` + `{sources:"x.csv"}` → `ingest --sources x.csv`; `eda` + `{no_auto_rebalance:True}` → `eda --no-auto-rebalance`; unknown flags for a stage are dropped.

- [ ] **Step 2: Run to verify fail** — `uv run pytest tests/dashboard/test_control.py -q` → FAIL.

- [ ] **Step 3: Implement**

Add a `build_command(stage, resume, settings)` pure helper (using a per-stage allowed-flag map derived from `stages.py`) and have `start` call it. Keep the control-file write and detached spawn as-is.

- [ ] **Step 4: Run to verify pass** — `uv run pytest tests/dashboard/test_control.py -q` → PASS.

- [ ] **Step 5: Ruff + commit**

```
git add src/cybersec_slm/dashboard/control.py tests/dashboard/test_control.py
git commit -m "feat(control): per-stage launch with stage-scoped advanced settings"
```

---

## Task A9: Phase parser reads the registry; full green + docs

**Files:**
- Modify: `src/cybersec_slm/dashboard/data.py` (`run_phase`/`_PHASE_DEFS` → `stages.phase_from_log`)
- Modify: `src/cybersec_slm/ingestion/README.md`, `cli.py` docstring (usage), root `README` if it lists `run`.
- Test: `tests/dashboard/test_data.py` (adjust phase expectations to five stages)

- [ ] **Step 1: Adjust the phase tests** to expect stage keys `source/ingest/clean/eda/schema` from `run_phase`.
- [ ] **Step 2: Run to verify fail** — `uv run pytest tests/dashboard/test_data.py -q` → FAIL.
- [ ] **Step 3: Reimplement `run_phase`** on top of `stages.phase_from_log`, keeping the `gate_failed`/`done` terminal handling; delete `_PHASE_DEFS`.
- [ ] **Step 4: Update docs** (usage blocks, remove `run`, describe the five stages).
- [ ] **Step 5: Full gate** — `uv run ruff check src tests` and `uv run pytest -q` → both PASS.
- [ ] **Step 6: Commit**

```
git add -A
git commit -m "refactor(dashboard): phase parser from stage registry; docs for five stages"
```

---

## Self-review notes

- Spec coverage: canonical registry (A1), physical ingest (A2-A4), clean+dedup fold (A5), all rewire + run removal (A6), CLI stages + flags (A7), per-stage control (A8), phase parser + docs (A9). Raw-delete-after-clean default is in A5; `--keep-raw` retained. All spec decisions map to a task.
- Risk concentration is A3 (pool extraction); it is guarded by running the whole existing `tests/ingestion` suite, not just the new test.
- Deferred to sub-project B (separate plan): the dashboard pages, `ui.py`, Overview, stable-layout/log work.
