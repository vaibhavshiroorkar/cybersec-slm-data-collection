# Commands

The complete command reference for the pipeline. The [README](../README.md) covers
the quickstart; this page is the detail — every stage, flag, and run mode, plus
Docker, configuration, and development.

Everything runs through one console script, `cybersec-slm` (installed by `uv sync`).
`python -m cybersec_slm <command>` is equivalent if you'd rather not use it.

## Setup

Requires Python 3.13+ and [uv](https://docs.astral.sh/uv/).

```bash
cp .env.example .env                    # add API keys (all optional for a basic run)
uv sync                                 # install the pipeline + dev tools
uv run playwright install chromium      # browser for the HTML crawler (extract html)
```

## Run the whole pipeline

```bash
uv run cybersec-slm all                 # extract → clean → EDA gate → normalize
```

`all` runs the streaming path: it fetches and cleans each source together, runs one
cross-source dedup pass, applies the EDA sufficiency gate (a blocker stops the run),
and rebuilds the canonical dataset. Output lands in `data/final/dataset.jsonl`.

## Run one stage at a time

```bash
uv run cybersec-slm extract all         # collect allowlisted sources       -> data/raw/
uv run cybersec-slm clean all           # clean + flag + drop + report       -> data/clean/
uv run cybersec-slm eda                 # validate corpus + sufficiency gate -> logs/eda/
uv run cybersec-slm normalize           # canonical 22-field dataset         -> data/final/
```

### Command summary

| Command | Purpose |
|---|---|
| `extract [scrape\|fetch\|html\|nvd\|all\|table]` | Fetch and normalize allowlisted sources → `data/raw/` |
| `clean [all\|sanitize\|dedup\|pii\|lang\|report\|balance]` | Clean the raw corpus → `data/clean/` (+ `data/flagged/`, `data/dropped/`) |
| `eda [--no-enforce] [--profile]` | Validate the corpus and apply the sufficiency gate → `logs/eda/` |
| `normalize [--fresh]` | Schema-normalize into `data/final/dataset.jsonl` + manifest |
| `run [--workers N]` | Parallel per-source fetch + clean (streaming) → `data/clean/` |
| `source [--dry-run]` | Discover sources via search engines → `sources/Sources.csv` |
| `flow [--dvc-push]` | Run the pipeline via Prefect (needs the `orchestration` extra) |
| `validate` | Check `data/clean/` records against the schema |
| `all` | Run the full pipeline, end to end |

### Per-command flags

**`extract <action>`** — `scrape` (PDFs + JSON feeds), `fetch` (HuggingFace / Kaggle
/ GitHub / raw URLs), `html` (crawlable sites, needs Chromium), `nvd` (the NVD CVE
feed), `all` (everything), `table` (print the per-source summary). Sources are read
from `sources/Sources.csv`; only rows approved in `sources/allowlist.yaml` are
fetched. `extract nvd` reads `NVD_API_KEY` from the environment for a higher rate
limit.

**`clean <action>`** — `all` runs the full chain; `sanitize` / `dedup` / `pii` /
`lang` run a single step; `report` recounts the existing `data/clean`, `data/flagged`,
and `data/dropped` trees; `balance` reports per-domain volume.
- `--limit N` — cap records per file (smoke test).
- `--cap N` — max records per domain (with the `balance` action).

**`eda`**
- `--input PATH` — cleaned-records root (default: `data/clean/`).
- `--no-enforce` — report only; don't fail the run on a blocker.
- `--profile` — also write a ydata-profiling HTML report (needs `ydata-profiling`,
  which requires pandas `<3`; run it in a throwaway env — see [Optional extras](#optional-extras)).

**`normalize`**
- `--input PATH` — cleaned-records root (default: `data/clean/`).
- `--fresh` — ignore any existing `dataset.jsonl` (don't resume/append).
- `--limit N` — cap records per file (smoke test).

**`run`** (parallel streaming fetch + clean)
- `--sources PATH` — a sources `.csv` (default: `sources/Sources.csv`).
- `--workers N` — process-pool size (default: `min(cpu, 8)`).
- `--limit N` — cap records per file.
- `--keep-raw` — keep `data/raw/` instead of deleting it after cleaning.
- `--no-final-dedup` — skip the final cross-source dedup pass.

**`source`** (search-engine source discovery)
- `--sources PATH` — catalog CSV to append to (default: `sources/Sources.csv`).
- `--domains ...` — limit to these Sub-Domains (default: all).
- `--mode datasets|text|both` — keyword catalog (default: `datasets`).
- `--per-keyword N` — results per keyword (≤10, default 5).
- `--max-per-domain N` — cap new rows kept per Sub-Domain.
- `--dry-run` — discover and write the candidate CSV but don't append to the catalog (`sources/Sources.csv`).
- `--out PATH` — path for the candidate CSV (default: `logs/discovered/`).
- `--api-key`, `--cse-id` — Google Programmable Search credentials (or set
  `GOOGLE_SEARCH_API_KEY` / `GOOGLE_SEARCH_ENGINE_ID`).

**`flow`** (Prefect orchestration — needs the `orchestration` extra)
- `--sources PATH` — path/URL to a sources file.
- `--no-enforce-eda` — run the EDA gate in report-only mode.
- `--dvc-push` — snapshot and push the dataset to the DVC remote.

## Two run modes

The same logical work runs two ways:

| | Sequential (`all`) | Parallel / streaming (`run`, `flow`) |
|---|---|---|
| Extraction + cleaning | all sources, then clean all | one process per source: fetch → clean → delete raw |
| Dedup | global, inline during cleaning | per-source workers skip it; one final cross-source pass |
| Output | `data/clean/` | `data/clean/` |

Both feed the same EDA gate and normalizer. See
[architecture.md](architecture/architecture.md) for what happens inside each stage.

## Docker

```bash
docker build -t cybersec-slm .
docker run --rm --env-file .env -v "$(pwd)/out:/work" cybersec-slm
```

On Windows PowerShell, mount the volume with `-v "${PWD}\out:/work"`. The image runs
as a non-root user and writes everything under the mounted volume — the corpus to
`out/data/` and run logs to `out/logs/`. Secrets are read from `--env-file` at
runtime and are never baked into the image. To run a single stage, append it after
the image name:

```bash
docker run --rm --env-file .env -v "$(pwd)/out:/work" cybersec-slm cybersec-slm extract all
```

See [operations/deploy.md](operations/deploy.md) for the AWS path (ECR / ECS /
Prefect Cloud).

## Configuration

Optional API keys are read from a `.env` file, auto-loaded at startup; shell
environment variables take precedence. None are required for a basic local run.

| Variable | Used by | Required? |
|---|---|---|
| `NVD_API_KEY` | `extract nvd` (higher CVE rate limit) | optional |
| `KAGGLE_API_TOKEN` | Kaggle sources | only for Kaggle sources |
| `GOOGLE_SEARCH_API_KEY`, `GOOGLE_SEARCH_ENGINE_ID` | `source` | only for sourcing |
| `CYBERSEC_SLM_DATA_ROOT` | all stages (where `data/` and `logs/` are written) | optional |
| `CYBERSEC_SLM_ENFORCE_ALLOWLIST` | extraction allowlist gate | optional |

EDA gate thresholds are environment-overridable too; see `src/cybersec_slm/eda/config.py`.

## Optional extras

```bash
uv sync --extra orchestration   # Prefect + prefect-aws (for `flow` and AWS deploy)
```

- **orchestration** powers `cybersec-slm flow` and the ECS deployment.
  `cybersec-slm all` runs the identical pipeline locally without it. It pulls in
  ~100 packages, and on Windows its `whenever` extension ships a DLL that Smart App
  Control may block — so it is opt-in.
- **profiling** (`ydata-profiling`, the optional `eda --profile` HTML report) pins
  pandas `<3.0`, which conflicts with the pipeline's pandas `>=3.0`. The EDA gate
  runs without it; for a one-off profile, use a throwaway environment:
  `uvx --with 'pandas<3' ydata-profiling`.

Every cleaning tool also has a standard-library fallback and logs which backend it
used, so a missing optional dependency degrades quality gracefully rather than
failing the run.

## Development

```bash
uv run pytest                  # full test suite
uv run ruff check src tests    # lint
```
