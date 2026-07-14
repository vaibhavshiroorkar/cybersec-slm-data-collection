# Dashboard UI redesign (all pages)

Date: 2026-07-14

## Goal

The dashboard works but reads as an unstructured wall of `subheader` + `divider`
sections that looks the same top to bottom. Restructure every page for a
consistent, scannable layout. Priority is structure and consistency, not
per-component polish; keep the change restrained (plain text only, no emoji).

## Direction

A quiet "instrument panel" read appropriate to a data pipeline: hairline-bordered
section cards, a consistent stage header carrying the pipeline's real
`Stage N of 5` sequence, and monospace tabular numerals in the stat tiles (the one
justified, subject-true flourish). One accent color, used sparingly.

## Design tokens

- **Color:** single primary accent `#4C6EF5` (indigo) set via
  `.streamlit/config.toml`. Surfaces use theme-neutral `rgba` so cards read
  correctly in both light and dark; semantic status stays green/red/amber and is
  carried by existing `st.success`/`st.error` + the status pill.
- **Type:** default sans for prose/labels; monospace with `tabular-nums` for stat
  values and the log. Card titles are a small uppercase "eyebrow" label.
- **Radius/spacing:** 0.6rem card radius, consistent internal padding, tighter
  top-of-page padding; dividers largely replaced by card borders.

## Shared scaffold (`ui.py`)

- `inject_css()` - refined: card border/padding/radius, eyebrow label, pill chip,
  monospace metric values, tighter headers.
- `page_header(stage_key, states)` - standardized stage header: `Stage N of 5`
  eyebrow, stage label as the title, and a status pill (`done`/`running`/
  `failed`/`pending`/`idle`) from `data.stage_states()`.
- `app_header(title, subtitle)` - header for the non-stage pages (Overview, Agent).
- `section(title, subtitle=None)` - context manager wrapping `st.container(
  border=True)` with an eyebrow title; pages use `with ui.section(...)：` instead
  of `subheader` + `divider`.
- Existing `stat_grid`, `table`, `log_box`, `stage_run_control`,
  `advanced_settings` keep their signatures (advanced_settings already carries the
  task-1 row controls); only styling changes around them.

`stage_header` is replaced by `page_header`; `stage_position` is reused.

## Per-page structure

- **Overview (`app.py`):** live status row (pinned fragment) → `Run the full
  pipeline` card → `Corpus funnel` card → `Pipeline log` card → `Sessions` card →
  `EDA gate` + `Release` cards. No divider walls.
- **Sourcing:** tabbed - `Discover | Catalog | Sub-domains | Delete rows |
  Sources.csv`. Each tab's blocks become cards. Tames the longest page.
- **Ingest:** cards - `Run this stage`, `Ingested (raw)` (stats), `Sources on
  disk`, `No data (and why)`.
- **Clean:** cards - `Run this stage`, `Cleaned`, `Cleaned sources`, `Where did
  my data go`.
- **EDA:** cards - `Run this stage`, `Sufficiency gate`, `Metrics`, `Trends`.
- **Schema:** tabbed - `Run | Manifest | Browse`. The paginated corpus browser
  lives in its own tab.
- **Agent:** `app_header` + a single conversation card; unchanged behavior.

## Theme file

New `.streamlit/config.toml` at the repo root (Streamlit reads it from the CWD the
dashboard is launched in):

```toml
[theme]
primaryColor = "#4C6EF5"
font = "sans serif"
```

Only the accent + font are set, so a viewer's light/dark choice is preserved.

## Non-goals

- No behavioral change to any run control, data read, or the agent.
- No new dependencies; pure Streamlit + CSS.
- Not a per-component visual overhaul; the aim is consistent structure.

## Verification

- Each page rendered headless via `streamlit.testing.v1.AppTest` with no
  exception, seeded with a temp data root.
- Full `pytest` suite stays green (existing `test_app_smoke`, `test_ui`, etc.).
