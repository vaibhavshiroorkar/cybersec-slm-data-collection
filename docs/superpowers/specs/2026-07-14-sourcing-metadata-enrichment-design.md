# Sourcing metadata enrichment

Date: 2026-07-14

## Goal

The source-discovery stage writes catalog rows with only what SearXNG returns
(Name, Sub-Domain, Description, Dataset Link, Category, Original Format, Date
Added). Fetch real per-source metadata at discovery time and fill it into
`Sources.csv`: size, license, last updated, and as many other parameters as each
host exposes.

## Fields

Fill these existing (currently-blank) columns:

- **License** - HF `cardData.license` / `license:*` tag; GitHub `license.spdx_id`.
- **Last Updated** - HF `lastModified`; GitHub `pushed_at`; direct URL
  `Last-Modified` header. Stored as `YYYY-MM-DD`.
- **Original Size (MB)** - HF sum of data-file sibling sizes; GitHub repo `size`
  (KB -> MB); direct URL `Content-Length`. Rounded to 2 dp.
- **File Count** - HF count of data files; direct URL = 1.

Add these new columns (extending the header, inserted before `Note`):

- **Author** - HF/GitHub owner or org; else the host.
- **Popularity** - HF `downloads` or GitHub `stargazers_count` (whichever applies).
- **Tags** - HF `tags` / GitHub `topics`, comma-joined, `license:*` and
  `size_categories:*` dropped, capped in length.

## Module: `sourcing/enrich.py`

`enrich_row(row, *, client=None, github_token=None, timeout=8.0) -> dict` inspects
`row["Dataset Link"]` and dispatches by host, returning the row with any fields it
could resolve filled in. Never raises: a network error, rate limit, or parse
failure logs at debug and leaves the field blank.

- `_enrich_hf(ref)` - `HfApi().dataset_info(ref, files_metadata=True)` (reuses the
  dependency `ingestion/fetch.py` already uses).
- `_enrich_github(owner, repo)` - `GET https://api.github.com/repos/{owner}/{repo}`
  via the shared `httpx` client; sends `Authorization: Bearer $GITHUB_TOKEN` when
  set (raises the 60/hour unauthenticated limit).
- `_enrich_url(url)` - `HEAD` for `Content-Length` / `Last-Modified`.

Host detection reuses the same URL patterns as `row._derive_name`.

## Wiring

- `run.discover(..., enrich: bool = True)` - after `build_row`, call
  `enrich_row` for each kept row (best-effort). A shared `httpx.Client` is created
  once per run and passed in. `github_token` read from `$GITHUB_TOKEN`.
- CLI `source`: add `--no-enrich`; wire `enrich=not args.no_enrich`.
- Dashboard: add `no_enrich` to `control._STAGE_FLAGS["source"]` and `_FLAG_SPEC`
  (`("no_enrich", "--no-enrich", "bool")`); render an "enrich discovered sources
  with metadata (size, license, ...)" checkbox (default on) in
  `ui.advanced_settings` for the source stage.
- `sheet.append_rows` - union in any columns present on the new rows but missing
  from an existing file's header (appended at the end), so the new columns are
  added to `Sources.csv` on the first enriched append. Order preserved otherwise.

## Behavior / limits

- On by default; opt out with `--no-enrich` or the dashboard toggle.
- One extra network call per kept row; failures never abort discovery.
- GitHub unauthenticated is 60/hour - honor `$GITHUB_TOKEN`; on 403/rate-limit,
  skip enrichment for the rest of the run (log once) rather than hammering.

## Testing

- `enrich_row` maps a stubbed HF `dataset_info` to License/Last Updated/Size/File
  Count/Author/Popularity/Tags; stubbed GitHub JSON likewise; a stubbed `HEAD`
  fills size/last-updated for a direct URL; every host path swallows errors.
- `append_rows` adds a new column when appending a row that carries it to an
  existing file, keeping existing rows blank in that column.
- `discover(enrich=True)` calls the enricher; `enrich=False` skips it.
- CLI parses `--no-enrich`; `build_command("source", {"no_enrich": True})` emits it.

## Out of scope

- Kaggle metadata (needs auth; left blank).
- Backfilling existing catalog rows (enrichment applies to newly discovered rows).
