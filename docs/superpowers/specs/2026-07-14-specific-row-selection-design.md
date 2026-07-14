# Specific-row selection for ingest and clean

Date: 2026-07-14

## Goal

Extend the existing selective-run controls so a run can be narrowed to specific
sources ("rows"), not just whole sub-domains, for the **ingest** and **clean**
stages. Sub-domain selection already exists (`--domains`); this adds a row layer
on top of it.

## Selection model

Each stage narrows the set of sources it processes with two combinable inputs:

1. **Sub-domain(s)** - the existing multiselect (`--domains`), unchanged.
2. **Specific rows** - a new per-source restriction, passed as `--sources-only`.

The two are intersected: chosen sub-domains, then narrowed to chosen rows. Empty
on both = the whole stage (today's behavior, unchanged).

### Row universe is stage-appropriate

Each stage reads from a different place, so its "rows" are the rows of whatever it
processes (mirrors the existing `catalog_subdomains` vs `raw_subdomains` split):

| | Ingest | Clean |
|---|---|---|
| Reads from | `sources/Sources.csv` (catalog) | `data/raw/` (fetched folders) |
| Row universe | catalog rows | `<sub-domain>/<source>` folders |
| Identity passed in `--sources-only` | Dataset Link (URL) = `descriptor_key` | `<sub-domain>/<source>` folder path |

### Selection widget (in `ui.advanced_settings`, ingest/clean only)

- **Sub-domain(s) selected** -> a nested "sources to run" multiselect listing only
  rows in the selected sub-domains. Empty = all rows in those sub-domains.
- **No sub-domain selected** -> a **start/end row-number range** over that stage's
  full list, matching the `#` shown in the stage's table. Ingest ranges over
  `Sources.csv` in file order; Clean ranges over its raw-folder list.

The widget resolves the selection to a concrete list of identities *before launch*.
`sources_only` is therefore always a resolved list; saving stage settings saves the
resolved identities (a saved selection is stable regardless of later catalog edits).

### Clean list ordering

For the Clean range to map to what the user sees, the Clean page's source list and
the range are presented in a **stable (sub-domain, source)** order, rather than the
current size-sorted order used by `raw_table`.

## Backend behavior

### `run_ingest(..., sources_only: list[str] | None = None)`

- After the existing `domains` filter, further filter descriptors to those whose
  `descriptor_key` (URL) is in `sources_only`.
- If the intersection is empty, log a warning and return the empty summary.
- **Fresh-run wipe:** when `sources_only` is set, do **no** directory wipe -
  surgically re-fetch just those sources (their fetch handlers overwrite their own
  folders). Rationale: HF/Kaggle folder names are computed statefully at fetch time
  (`fetch._folder`), so pre-wiping individual source folders is fragile. Whole
  sub-domain wipe still applies when only `domains` (no `sources_only`) is set.

### `run_clean(..., sources_only: list[str] | None = None)`

- When `sources_only` is set, clean exactly those `<sub-domain>/<source>` raw
  folders (via `clean_one_source` per folder) instead of whole sub-domain dirs.
- **Fresh-run wipe:** wipe only the selected sources' `data/clean/<sub-domain>/
  <source>` output folders (cleanly computable from the folder paths).
- `keep_raw=False` deletes only the selected raw source folders.
- The cross-source dedup pass still runs over the whole `data/clean/` tree.

## CLI

Add `--sources-only` (`nargs="*"`, default `None`) to both the `ingest` and
`clean` subparsers, wired through to `run_ingest` / `run_clean`.

- ingest help: "fetch only these specific sources (by Dataset Link/URL); combine
  with --domains to scope within sub-domains".
- clean help: "clean only these specific source folders (`sub-domain/source`)".

## Dashboard plumbing (`control.py`)

- Add `sources_only` to `_STAGE_FLAGS["ingest"]` and `_STAGE_FLAGS["clean"]`.
- Add `("sources_only", "--sources-only", "list")` to `_FLAG_SPEC` (after
  `domains`, so its greedy `nargs="*"` never swallows another flag's value).

## Data helpers (`data.py`)

- Catalog rows for the ingest picker: reuse `catalog_rows()`; expose each row's
  Dataset Link and Sub-Domain for building the nested/ranged options.
- Raw folders for the clean picker: a stable `(sub-domain, source)`-ordered list
  derived from `raw_table()`.

## Testing

- `build_command` emits `--sources-only a b` for ingest/clean and drops it for
  other stages (mirrors the `--domains` tests).
- `run_ingest` filters descriptors by URL membership; empty intersection returns
  the empty summary and wipes nothing.
- `run_clean` cleans only the selected source folders and wipes only their clean
  output on a fresh run.

## Out of scope

- The full UI redesign (task 2) - a separate spec. This change adds the controls
  in the current layout; the redesign will absorb them.
- Row selection for `source`, `eda`, `schema` stages (not requested).
