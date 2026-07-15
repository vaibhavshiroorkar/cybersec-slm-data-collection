# Dashboard settings: simple / advanced two-tier split

Date: 2026-07-15

## Goal

Make the dashboard's per-stage run settings easier to use by splitting them into
two tiers, tuning the default seeds so the common tier is usually left untouched,
and removing redundant widgets. No change to pipeline behavior.

## Current state

Every stage page and the Overview override panel render their run knobs through
one shared helper, `ui.advanced_settings(stage)`, which puts all of a stage's
flags inside a single "Advanced settings" expander. Which flags a stage accepts
is defined by `control._STAGE_FLAGS`. Problems:

- Common and rarely-touched knobs are mixed together in one expander.
- Source shows `time budget` and `max new sources` twice: once as headline
  controls on the Sourcing page, once again inside the expander (dead copies).
- `target_per_domain` and `engines` are live source flags (in `_STAGE_FLAGS` and
  `_FLAG_SPEC`) but have no widget, so they are only reachable via saved JSON or
  the CLI.
- The ingest/all `workers` widget seeds to 4, while the CLI default is
  `min(cpu, 8)`.

## Design

### Two-tier renderer

Add a per-stage `_COMMON` classification to `ui.py`. `advanced_settings` renders
the Common flags inline (above the expander) and the remaining accepted flags
inside the existing "Advanced settings" expander. There is no global mode toggle
and no persisted mode: simplicity comes from layering, and strong defaults keep
the Common tier short.

Keep the widget-building logic in one place. Each flag's widget is emitted into
either the inline block or the expander based on membership in `_COMMON[stage]`.
The classification is a plain dict, so a pure helper that partitions a stage's
accepted flags into (common, advanced) is unit-testable without Streamlit,
matching the module's existing "keep logic testable" pattern.

### Per-stage classification

| Stage | Common (inline) | Advanced (expander) |
|-------|-----------------|---------------------|
| source | domains, mode, max_minutes, max_total, target_per_domain | workers, per_keyword, max_per_domain, engines, time_range, no_site_scope, no_quality_filter, no_enrich, searxng_url, language, dry_run |
| ingest | domains, no_crawler | workers, source_timeout, max_source_gb, limit, sources, sources_only |
| clean | domains | drop_non_english, purge_raw, limit, sources_only |
| eda | no_auto_rebalance | no_enforce |
| schema | (none) | fresh, limit |
| all | workers, no_crawler | source_timeout, max_source_gb, limit, purge_raw, drop_non_english, no_auto_rebalance, sources |

Where each tier renders differs by stage:

- For every non-source stage the whole split lives inside the shared helper:
  `advanced_settings` renders that stage's Common flags inline, then the Advanced
  flags in the expander.
- For source the Common tier is rendered by the Sourcing page itself, because the
  page needs the selected sub-domains and mode to build the "Keywords that will
  run" preview before it calls the helper. So the source Common row in the table
  describes the page's headline controls; `advanced_settings("source")` renders
  the Advanced set only and must not re-render domains, mode, `max_minutes`,
  `max_total`, or `target_per_domain`. The duplicate `max_minutes` / `max_total`
  copies are removed from `advanced_settings` for source accordingly.

### Added widgets

- `target_per_domain` (Common, source): integer headline control on the Sourcing
  page, fill each sub-domain up to this many commercial-valid rows; 0 disables.
  Seeded from saved settings and passed in the source settings dict. Mirrors the
  CLI `--target-per-domain`.
- `engines` (Advanced, source): text input inside `advanced_settings`,
  comma-separated SearXNG engines; blank falls back to env / the reliable default
  set. Mirrors `--engines`.

### Default seed changes

- ingest / all `workers`: seed 4 becomes 8 (aligns with the CLI's `min(cpu, 8)`).

All other current defaults are retained: crawler ON, enrich ON, quality filter
ON, site-scope ON, freshness = year, EDA auto-rebalance OFF, EDA enforce ON.

## Non-goals

- No global simple/advanced toggle.
- No change to `control._STAGE_FLAGS`, the CLI, or any stage's runtime behavior.
- No write to the user's saved `pipeline_settings.json`; defaults are widget
  seeds only, used when nothing is saved.
- No behavior-changing default flips (auto-rebalance stays OFF, enforce stays ON).

## Implementation surface

- `src/cybersec_slm/dashboard/ui.py`: add `_COMMON`, split `advanced_settings`
  into an inline Common block and the Advanced expander; add the two new source
  widgets; change the `workers` seed.
- `src/cybersec_slm/dashboard/pages/1_Sourcing.py`: add the `target_per_domain`
  headline control (Common), seeded from saved settings and included in the source
  settings dict; remove the now-duplicated `max_minutes` / `max_total` handling
  that compensated for the expander copies, keeping the headline controls as the
  single source of those two values.

## Testing

- Unit-test the pure partition helper (accepted flags split into common vs
  advanced per stage) in `tests/dashboard/test_ui.py`, with no Streamlit import.
- Confirm the existing dashboard test suite still passes (the settings that
  `advanced_settings` returns are unchanged; only where each widget renders
  changes).
- Re-run the wiring dry test (all stage commands still parse through argparse).
