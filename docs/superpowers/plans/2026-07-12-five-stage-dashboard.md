# Five-Stage Dashboard (Sub-project B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the Streamlit dashboard to follow the five-stage model: an Overview of all stats plus one page per stage, with a stable (non-jumping) layout, scrollable logs, per-stage run controls, and advanced settings.

**Architecture:** A shared `dashboard/ui.py` (CSS + helpers) keeps every page visually identical and short. `data.py` gains a `stage_states()` reader over the stage registry. `app.py` becomes the Overview; `pages/1_Sourcing.py` .. `5_Schema.py` are one-per-stage from a shared template; Dataset and Agent move to `6_` and `7_`. Auto-refresh regions live in fixed-height containers so values change in place without reflowing.

**Tech Stack:** Streamlit (multipage), `streamlit.testing.v1.AppTest` for render smoke tests, pytest, ruff, uv.

## Global Constraints

- Ruff must pass: `uv run ruff check src tests`. Line length <= 100.
- Tests must pass: `uv run pytest -q`.
- No em dashes in comments, docs, or UI copy.
- No Claude attribution in commit messages.
- Pages are presentation-only: every value comes from `dashboard/data.py` or `dashboard/control.py` (no direct artifact reads in page scripts).
- Reads the canonical stages from `cybersec_slm.stages`.
- Builds on sub-project A (already merged into this branch): `stages`, `control.start(stage=..., settings=...)`, `control.build_command`, `data.run_phase` (stage keys).

---

## File structure

- Create `src/cybersec_slm/dashboard/ui.py` — CSS injection + presentation helpers.
- Modify `src/cybersec_slm/dashboard/data.py` — add `stage_states()` (+ `_artifact_done`).
- Rewrite `src/cybersec_slm/dashboard/app.py` — Overview (all stats + launcher).
- Create `pages/1_Sourcing.py`, `2_Ingest.py`, `3_Clean.py`, `4_EDA.py`, `5_Schema.py`.
- Rename `pages/2_Dataset.py` -> `pages/6_Dataset.py`; `pages/3_Agent.py` -> `pages/7_Agent.py`.
- Delete `pages/1_Pipeline.py` (its content is split across the stage pages + Overview).
- Tests: `tests/dashboard/test_data.py` (stage_states), `tests/dashboard/test_ui.py` (helpers), `tests/dashboard/test_app_smoke.py` (reparametrize over the new pages).

---

## Task B1: `stage_states()` read-layer helper

**Files:**
- Modify: `src/cybersec_slm/dashboard/data.py`
- Test: `tests/dashboard/test_data.py`

**Interfaces:**
- Produces: `stage_states() -> dict[str, dict]` keyed by the five stage keys, each `{"state": "done"|"running"|"failed"|"pending", "detail": str}`. Derived from `run_phase()` + `run_status()` (live/last phase) and per-stage artifact presence (`_artifact_done(key)`): source=catalog non-empty; ingest=`_ingest_ledger_stats()["sources"] > 0` or `_completed_count() > 0`; clean=`clean_report()["total"]` present; eda=`latest_eda()` present; schema=`manifest()` present. `gate_failed` marks `eda` as `failed`.

- [ ] **Step 1: Write the failing test**

```python
def test_stage_states_all_done_when_artifacts_present(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs"; (logs / "eda").mkdir(parents=True)
    (logs / "completed_sources.txt").write_text("a\n", encoding="utf-8")
    (logs / "clean_report.csv").write_text(
        "sub_domain,source,file,in,out\nTOTAL,,1 files,10,8\n", encoding="utf-8")
    (logs / "eda" / "latest.json").write_text('{"passed": true}', encoding="utf-8")
    final = tmp_path / "data" / "final"; final.mkdir(parents=True)
    (final / "manifest.json").write_text('{"record_count": 8}', encoding="utf-8")
    monkeypatch.setattr(data, "_catalog_total", lambda: 5)
    st = data.stage_states()
    assert set(st) == {"source", "ingest", "clean", "eda", "schema"}
    assert st["clean"]["state"] == "done"
    assert st["schema"]["state"] == "done"

def test_stage_states_gate_failed_marks_eda(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    logs = tmp_path / "logs"; logs.mkdir()
    (logs / "pipeline.1.log").write_text(
        "x - eda: total=10\nx:1 - EDA sufficiency gate FAILED: 1 blocker\n",
        encoding="utf-8")
    assert data.stage_states()["eda"]["state"] == "failed"
```

- [ ] **Step 2: Run to verify fail** — `uv run pytest tests/dashboard/test_data.py -k stage_states -q` → FAIL (`stage_states` missing).

- [ ] **Step 3: Implement `_artifact_done` + `stage_states`**

```python
def _artifact_done(key: str) -> bool:
    if key == "source":
        return bool(_catalog_total())
    if key == "ingest":
        return _ingest_ledger_stats()["sources"] > 0 or _completed_count() > 0
    if key == "clean":
        return clean_report().get("total") is not None
    if key == "eda":
        return latest_eda() is not None
    if key == "schema":
        return manifest() is not None
    return False


def stage_states() -> dict:
    ph = run_phase()
    running = run_status()["state"] == "running"
    pk = ph.get("phase")
    keys = stages.stage_keys()
    out: dict[str, dict] = {}
    if pk == "gate_failed":
        for i, k in enumerate(keys):
            if k == "eda":
                out[k] = {"state": "failed", "detail": ph.get("detail", "")}
            else:
                out[k] = {"state": "done" if i < keys.index("eda") else "pending",
                          "detail": ""}
        return out
    cur = keys.index(pk) if pk in keys else -1
    for i, k in enumerate(keys):
        if running and i == cur:
            state = "running"
        elif i < cur or _artifact_done(k):
            state = "done"
        else:
            state = "pending"
        out[k] = {"state": state, "detail": ph.get("detail", "") if i == cur else ""}
    return out
```

- [ ] **Step 4: Run to verify pass** — `uv run pytest tests/dashboard/test_data.py -k stage_states -q` → PASS.

- [ ] **Step 5: Ruff + commit**

```
git add src/cybersec_slm/dashboard/data.py tests/dashboard/test_data.py
git commit -m "feat(dashboard): stage_states read-layer helper over the stage registry"
```

---

## Task B2: `ui.py` shared presentation helpers

**Files:**
- Create: `src/cybersec_slm/dashboard/ui.py`
- Test: `tests/dashboard/test_ui.py`

**Interfaces:**
- Produces (pure, testable): `status_pill(state: str) -> str` returns a markdown pill string with an emoji per state (`done`✅/`running`🟢/`pending`○/`failed`⛔/`idle`○). `PILL` emoji map. Streamlit-touching helpers (`inject_css()`, `log_box(lines, height=320)`, `stat_grid(pairs, cols)`, `stage_header(key, states)`, `run_controls(stage, running, settings_widgets)`) import streamlit lazily so the module imports without the extra.

- [ ] **Step 1: Write the failing test** (only the pure helper is unit-tested; the rest are covered by the page smoke tests)

```python
from cybersec_slm.dashboard import ui

def test_status_pill_has_emoji_per_state():
    assert "✅" in ui.status_pill("done")
    assert "⛔" in ui.status_pill("failed")
    assert ui.status_pill("nonsense")  # never raises, returns a default
```

- [ ] **Step 2: Run to verify fail** — `uv run pytest tests/dashboard/test_ui.py -q` → FAIL.

- [ ] **Step 3: Implement `ui.py`**

Define `PILL = {"done": "✅", "running": "🟢", "pending": "○", "failed": "⛔", "idle": "○"}`; `LABEL` map; `status_pill(state)` returns `f"{PILL.get(state, '○')} {state}"`. `inject_css()` injects one `<style>` (consistent card padding, a `.logbox` monospace look, tighter metric spacing) via `st.markdown(..., unsafe_allow_html=True)`, guarded so it runs once per session (`st.session_state`). `log_box(lines, height=320)` does `with st.container(height=height): st.code("\n".join(lines) or "(no log yet)", language="log")`. `stat_grid(pairs, cols=4)` lays `st.columns(cols)` and `st.metric` in a stable grid. `stage_header(key, states)` renders the stage label + `status_pill`. Each streamlit-touching helper does `import streamlit as st` inside the function.

- [ ] **Step 4: Run to verify pass** — `uv run pytest tests/dashboard/test_ui.py -q` → PASS.

- [ ] **Step 5: Ruff + commit**

```
git add src/cybersec_slm/dashboard/ui.py tests/dashboard/test_ui.py
git commit -m "feat(dashboard): shared ui helpers (status pill, scrollable log box, css)"
```

---

## Task B3: Overview page (app.py)

**Files:**
- Rewrite: `src/cybersec_slm/dashboard/app.py`
- Test: `tests/dashboard/test_app_smoke.py` (app.py already parametrized)

**Interfaces:**
- Consumes: `data.run_status`, `data.run_timing`, `data.stage_states`, `data.data_funnel`, `data.latest_eda`, `data.manifest`, `charts.*`, `control.status/start/stop/reset`, `ui.*`.

- [ ] **Step 1: Rewrite app.py**

Fixed skeleton, all values via `data`: (1) title + data-root caption; (2) a single `@st.fragment(run_every=3)` "live" region containing the run-status row (`stat_grid`: State, Stage, Elapsed/ETA) and the five-chip stage strip (`stage_states` -> `status_pill` per stage in `st.columns(5)`); (3) funnel headline `stat_grid` (Sources/Ingested/Cleaned/Final records); (4) EDA gate summary (pass/fail + key metrics); (5) manifest headline; (6) the full-pipeline launcher: Start / Resume / Stop / Reset buttons + an `st.expander("Advanced settings")` with widgets (workers, source-timeout, limit, keep-raw, disable-rebalance) whose values are passed as `control.start("all", settings=...)`. Call `ui.inject_css()` first.

- [ ] **Step 2: Run the smoke test** — `uv run pytest tests/dashboard/test_app_smoke.py -k app -q`
Expected: PASS (`assert not at.exception`).

- [ ] **Step 3: Ruff + commit**

```
git add src/cybersec_slm/dashboard/app.py
git commit -m "feat(dashboard): Overview page - all stats + full-pipeline launcher"
```

---

## Task B4: Sourcing + Ingest pages

**Files:**
- Create: `src/cybersec_slm/dashboard/pages/1_Sourcing.py`, `pages/2_Ingest.py`
- Test: `tests/dashboard/test_app_smoke.py` (add both to the parametrize list)

**Interfaces:**
- Consumes: `ui.*`, `data.*`, `control.start(stage=..., settings=...)`, `control.status`. Each page: `ui.inject_css()`; `ui.stage_header`; a run-control row (`[Run this stage]` -> `control.start("<stage>", settings=...)`, `[Stop]` when running, advanced-settings expander with only that stage's flags); `ui.log_box(data.log_tail(200))` in a fragment; then stage detail.

- [ ] **Step 1: Add both scripts to the smoke parametrize** in `test_app_smoke.py`:
`["app.py", "pages/1_Sourcing.py", "pages/2_Ingest.py", "pages/6_Dataset.py", "pages/7_Agent.py"]` (Dataset/Agent renamed in B6; add them there - for this task include only `1_Sourcing.py` and `2_Ingest.py`).

- [ ] **Step 2: Run to verify fail** — `uv run pytest tests/dashboard/test_app_smoke.py -q` → FAIL (files missing).

- [ ] **Step 3: Implement the two pages**
  - Sourcing: catalog summary via `data.catalog_summary()` (total + per-Sub-Domain bar via `st.bar_chart`), and a `[Discover sources]` control (`control.start("source")`). Note sourcing needs Google keys; show a caption saying so.
  - Ingest: `stat_grid` of raw stats from `data.data_funnel()["raw"]` (sources, records, size) and the per-source ingest ledger via `data.source_table()` in a fixed-height `st.container`; run control launches `control.start("ingest", settings=...)`.

- [ ] **Step 4: Run to verify pass** — `uv run pytest tests/dashboard/test_app_smoke.py -q` → PASS.

- [ ] **Step 5: Ruff + commit**

```
git add src/cybersec_slm/dashboard/pages/1_Sourcing.py src/cybersec_slm/dashboard/pages/2_Ingest.py tests/dashboard/test_app_smoke.py
git commit -m "feat(dashboard): Sourcing + Ingest stage pages"
```

---

## Task B5: Clean + EDA + Schema pages

**Files:**
- Create: `pages/3_Clean.py`, `pages/4_EDA.py`, `pages/5_Schema.py`
- Test: `tests/dashboard/test_app_smoke.py` (add the three)

**Interfaces:**
- Consumes: same helpers as B4 plus `data.data_funnel`, `data.clean_report`, `data.loss_breakdown`, `data.latest_eda`, `data.eda_history`, `charts.eda_trend_rows`, `data.normalize_report`, `data.manifest`.

- [ ] **Step 1: Add the three scripts to the smoke parametrize.**
- [ ] **Step 2: Run to verify fail** — `uv run pytest tests/dashboard/test_app_smoke.py -q` → FAIL.
- [ ] **Step 3: Implement**
  - Clean: `stat_grid` cleaned records/size + a `[Run clean]` control (keep-raw / resume expander); the clean-report breakdown and `data.loss_breakdown()` tables ("Dropped by mechanism", per-source losses) in fixed-height containers.
  - EDA: `[Re-run EDA]` control (disable-rebalance / no-enforce); the sufficiency gate (pass/fail + violations), the metrics `stat_grid`, trends (`st.line_chart` from `charts.eda_trend_rows(data.eda_history())`), and feedback recommendations.
  - Schema: `[Re-run normalize]` control; the normalize report counts and the release manifest (records/tokens, by-domain, by-license).
- [ ] **Step 4: Run to verify pass** — `uv run pytest tests/dashboard/test_app_smoke.py -q` → PASS.
- [ ] **Step 5: Ruff + commit**

```
git add src/cybersec_slm/dashboard/pages/3_Clean.py src/cybersec_slm/dashboard/pages/4_EDA.py src/cybersec_slm/dashboard/pages/5_Schema.py tests/dashboard/test_app_smoke.py
git commit -m "feat(dashboard): Clean + EDA + Schema stage pages"
```

---

## Task B6: Renumber Dataset/Agent, drop old Pipeline page, final gate

**Files:**
- Rename: `pages/2_Dataset.py` -> `pages/6_Dataset.py`; `pages/3_Agent.py` -> `pages/7_Agent.py`
- Delete: `pages/1_Pipeline.py`
- Modify: `tests/dashboard/test_app_smoke.py` (final parametrize list + the Agent test path)
- Modify: `src/cybersec_slm/dashboard/app.py` "Where to go" copy if it names pages; `dashboard/README.md`.

- [ ] **Step 1: Rename the two pages and delete `1_Pipeline.py`** (via `git mv` / `git rm`).
- [ ] **Step 2: Update `test_app_smoke.py`** parametrize to the final set (`app.py`, `pages/1_Sourcing.py` .. `5_Schema.py`, `pages/6_Dataset.py`) and repoint the Agent test to `pages/7_Agent.py`.
- [ ] **Step 3: Update `dashboard/README.md`** to describe Overview + five stage pages + Dataset + Agent.
- [ ] **Step 4: Full gate** — `uv run ruff check src tests` and `uv run pytest -q` → both PASS.
- [ ] **Step 5: Commit**

```
git add -A
git commit -m "feat(dashboard): renumber Dataset/Agent; drop old Pipeline page; docs"
```

---

## Self-review notes

- Spec coverage: Overview all-stats + launcher (B3); page-per-stage from a shared template (B4-B5); scrollable logs (`ui.log_box`, B2); stable layout (fixed-height containers + one fragment per page); per-stage run controls with stage-scoped advanced settings (B4-B5, on top of A8's `control.start(stage,...)`); `ui.py` + `data.stage_states` (B1-B2). Nav order via filename prefixes (B4-B6).
- Streamlit pages are verified by `AppTest ... assert not at.exception`, the existing project pattern; pure helpers (`status_pill`, `stage_states`) are unit-tested.
- The old four independent `run_every=2` fragments are replaced by one `run_every=3` fragment per page over a stable skeleton (the "no jumping" requirement).
