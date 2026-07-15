# Per-stage config modals on the Overview page

Date: 2026-07-15

## Goal

Consolidate all per-stage run configuration into modals launched from the
Overview (main) page, and turn the five stage pages into inspection-only views.
After this change, every stage's settings are edited in one place (a modal beside
that stage on the Overview page), and no stage can be launched from its own page.
Running is done from the Overview page: the full pipeline via Start/Resume, with
the existing per-stage skip toggles.

## Current state

- `app.py` (Overview) runs the full pipeline: Start/Resume/Stop/Reset plus a
  multi-select `st.pills` (`overview_stage_pills`) that chooses which stages run.
- Each stage page renders its own run controls and settings:
  - `2_Ingest`, `3_Clean`, `4_EDA`, `5_Schema` call `ui.stage_run_control(stage)`,
    which renders `ui.advanced_settings(stage)` (an "Advanced settings" expander)
    plus Run / Stop buttons that call `control.start(stage, ...)`.
  - `1_Sourcing` (Discover tab) renders headline caps (time budget, max new
    sources), a sub-domain / mode picker with a live "Keywords that will run"
    preview, `ui.advanced_settings("source")`, and Run discovery / Stop buttons.
  - `1_Sourcing` (Licenses tab) has a "Backfill licenses" button that launches the
    source stage in backfill mode, plus instant (no-run) blacklist / delete tools.
- `ui.advanced_settings(stage)` renders only the flags a stage accepts (per
  `control._STAGE_FLAGS`), seeded from `settings_store.get_stage(stage)`, with a
  "Save as defaults" button. For source it deliberately omits domains / mode /
  max_minutes / max_total because the Sourcing page renders those as headline
  controls.
- `settings_store` persists per-stage settings; `control.build_full_plan` layers
  Overview overrides on each stage's saved settings for the full run.

## Design

### Overview page (`app.py`)

Keep the "Run the full pipeline" section unchanged: Start / Resume / Stop / Reset
and the `overview_stage_pills` run/skip selector keep their current keys and
behavior.

Add a new row of five **Advanced** buttons directly beneath the pills, one per
stage, laid out in five equal columns so each button sits under its stage's pill.
Each button, when clicked, opens that stage's config modal by calling the shared
dialog function with that stage key. The buttons are labeled with the stage name
(e.g. "Sourcing settings") and carry stable keys (`cfg_<stage>`).

Only one dialog function is defined per script run; it is parametrized by stage,
so any of the five buttons opens the same function with a different argument. No
run action lives in this row: it is configuration only.

### The modal (`ui.py`)

Add `stage_config_dialog(stage)`, decorated with `@st.dialog`, titled
`Configure <Stage label>`. It:

1. Loads the stage's saved settings via `settings_store.get_stage(stage)`.
2. Renders **every** flag the stage accepts (all of `_STAGE_FLAGS[stage]`) through
   a shared widget body, seeded from those saved settings.
3. Shows a single "Save as defaults" button that persists the collected settings
   via `settings_store.save_stage(stage, settings)`, toasts confirmation, and
   closes the dialog (`st.rerun()`).

No Run button appears in the modal.

Refactor the widget-building logic out of the existing `advanced_settings` into a
pure-ish helper `_stage_widgets(stage, base) -> dict` that emits the Streamlit
widgets for the stage's accepted flags and returns the settings dict. Both the
old expander and the new dialog would otherwise duplicate this body, so it lives
in one function. For **source**, `_stage_widgets` now also renders the controls
that were previously the Sourcing page's headline widgets, so the modal truly
configures everything:

- sub-domains multiselect (`domains`)
- mode selectbox (`mode`)
- target-per-domain (`target_per_domain`)
- time budget minutes (`max_minutes`)
- max new sources (`max_total`)

These join the source flags `_stage_widgets` already handled (workers,
per_keyword, max_per_domain, engines, time_range, site-scope, quality-filter,
enrich, searxng_url, language, dry_run). Backfill-only flags (`backfill`,
`backfill_all`, `no_blacklist`) are not rendered as widgets (they were never
rendered before and are driven by the removed Licenses backfill action).

Remove the now-unused `advanced_settings` (expander) and `stage_run_control`
helpers. Their widget logic moves into `_stage_widgets`; the run-button logic is
deleted because no page runs a stage anymore. Update the `README.md` line that
lists `ui.py` helpers accordingly.

`save_settings_button` and `right_slot` remain (still used by the Sourcing
sub-domain editor and Schema fields editor). The dialog uses its own inline Save
button rather than `save_settings_button` so the button can also close the dialog.

### Stage pages: inspection only

`2_Ingest.py`, `3_Clean.py`, `4_EDA.py`:
- Delete the `with ui.section("Run this stage"): ui.stage_run_control(...)` block.
- Update the page caption to point at the Overview page for running (for example
  "Run this stage from the Overview page.").

`5_Schema.py`:
- In the "Run" tab, delete the `ui.section("Run this stage")` run control. Keep the
  Normalization stats block. Rename the tab from "Run" to "Normalize".

`1_Sourcing.py`, Discover tab:
- Remove the "Run discovery" / "Stop" buttons, the running-status caption, the
  headline caps (`src_minutes`, `src_maxtotal`), and the `ui.advanced_settings(
  "source")` call and the settings assembly around them.
- Keep the sub-domain multiselect and mode selectbox and the "Keywords that will
  run" preview. These now serve only as a catalog explorer for previewing which
  keywords a run would use. Seed their defaults from saved source settings as
  today. Add a caption noting the actual run uses the settings saved in the
  Overview page's Sourcing modal.

`1_Sourcing.py`, Licenses tab:
- Remove the "Backfill licenses" button and its inputs (`bf_all`, `bf_no_bl`,
  `bf_limit`) and the surrounding run-status caption.
- Keep the license-coverage stat grid, the "Clean up by license" instant tools
  (blacklist confirmed-red, delete blank-license), and the Blacklist view.

All other Sourcing tabs (Catalog, Sub-domains, Delete rows, Sources.csv) are
unchanged, as are the funnel, pipeline-log, EDA-gate, and release panels.

## Non-goals

- No change to `control._STAGE_FLAGS`, `build_command`, `build_full_plan`, the
  full-run orchestrator, or any stage's runtime behavior.
- No change to the CLI.
- No change to `settings_store`'s format or location.
- No new ability to run a single stage from the Overview page (running stays
  full-pipeline with skip toggles, per the chosen layout).
- `control.start(stage, ...)` for a single stage remains in the module (used by
  tests and available programmatically) even though no page calls it now.

## Implementation surface

- `src/cybersec_slm/dashboard/ui.py`: add `stage_config_dialog`; extract
  `_stage_widgets`; add the five source headline widgets to the source branch;
  remove `advanced_settings` and `stage_run_control`.
- `src/cybersec_slm/dashboard/app.py`: add the five Advanced buttons row and wire
  each to open `stage_config_dialog(stage)`.
- `src/cybersec_slm/dashboard/pages/1_Sourcing.py`: strip the discovery run and
  source settings; keep the keyword preview; strip the license backfill run.
- `src/cybersec_slm/dashboard/pages/2_Ingest.py`,
  `.../3_Clean.py`, `.../4_EDA.py`, `.../5_Schema.py`: remove the run sections;
  fix captions; rename Schema's tab.
- `src/cybersec_slm/dashboard/README.md`: update the `ui.py` helper list.

## Testing

- Existing `test_overview_stage_pills_default_to_all_five_lit` stays green (pills
  unchanged).
- `test_page_renders_without_error` (all six scripts) stays green after the edits.
- Add: opening a stage's modal and clicking "Save as defaults" persists the
  expected settings via `settings_store.get_stage(stage)`. Drive the dialog with
  `AppTest` by clicking the `cfg_<stage>` button, then the modal's save button.
- Add: the inspection pages (`2_Ingest`, `3_Clean`, `4_EDA`) expose no Run button
  (assert no button whose label starts with "Run").
- Confirm the full dashboard test suite passes.
