# Cybersecurity SLM Data Pipeline

A reproducible pipeline that gathers cybersecurity text from across the web and
turns it into a clean, schema-standardized, training-ready corpus for a small
language model (SLM).

It runs as five stages you can invoke individually or end to end:

| Stage | What it does | Output |
|---|---|---|
| **Sourcing** *(optional)* | Search engines by keyword → a reviewed tracking sheet of candidate sources | tracking sheet + `logs/discovered/` |
| **Extraction** | Pull each *allowlisted* source (datasets, PDFs, feeds, crawlable sites) and normalize to JSONL | `raw_data/` |
| **Cleaning** | Sanitize, flag anomalies, drop duplicates, redact PII, translate non-English → English | `clean_data/`, `flagged/`, `dropped/` |
| **EDA** | Validate the corpus (volume, balance, concentration, drift, duplicates) behind a sufficiency gate | `logs/eda/` |
| **Normalization** | Map every record onto the canonical 22-field schema, hash, near-dedup, write a provenance manifest | `final_data/dataset.jsonl` + `manifest.json` |

The pipeline is an installable Python package (`cybersec_slm`) with a single CLI.
Security is built into each stage — a version-controlled source allowlist, PII
redaction, metadata-only reject logs, content hashing, and a provenance manifest —
and an optional Prefect + DVC layer runs the whole thing on AWS.

For a full walk-through of how it works, see **[docs/architecture.md](docs/architecture.md)**.

## Quickstart

Requires Python 3.13+ and [uv](https://docs.astral.sh/uv/).

```bash
cp .env.example .env                    # add API keys (all optional for a basic run)
uv sync                                 # installs the whole pipeline + dev tools
uv run playwright install chromium      # browser for the HTML crawler (extract html)
```

Run the full pipeline:

```bash
uv run cybersec-slm all                 # extract → clean → EDA gate → normalize
```

…or one stage at a time:

```bash
uv run cybersec-slm extract all         # collect allowlisted sources       -> raw_data/
uv run cybersec-slm clean all           # clean + flag + drop + report       -> clean_data/
uv run cybersec-slm eda                 # validate corpus + sufficiency gate -> logs/eda/
uv run cybersec-slm normalize           # canonical 22-field dataset         -> final_data/
```

Output folders are created at the project root and are git-ignored. Point them
elsewhere with `CYBERSEC_SLM_DATA_ROOT`. If you'd rather not use the console
script, `python -m cybersec_slm <command> ...` works the same way.

### Commands at a glance

| Command | Purpose |
|---|---|
| `extract [scrape\|fetch\|html\|nvd\|all\|table]` | Fetch + normalize allowlisted sources |
| `clean [all\|sanitize\|dedup\|pii\|lang\|report\|balance]` | Clean the raw corpus |
| `eda [--no-enforce] [--profile]` | Validate corpus + sufficiency gate |
| `normalize [--fresh]` | Schema-normalize → `dataset.jsonl` + manifest |
| `run [--workers N]` | Parallel per-source fetch + clean (streaming) |
| `source [--dry-run]` | Search engines → tracking sheet |
| `flow [--dvc-push]` | Same pipeline via Prefect (needs the `orchestration` extra) |
| `validate` | Check `clean_data/` records against the schema |
| `all` | Full pipeline, end to end |

## Docker

```bash
docker build -t cybersec-slm .
docker run --rm --env-file .env -v "$(pwd)/data:/data" cybersec-slm
```

On Windows PowerShell, mount the volume with `-v "${PWD}\data:/data"`. The image
runs as a non-root user, writes outputs to the mounted `/data` volume, and reads
secrets at runtime (never baked into the image). To run a single stage, append it
after the image name, e.g. `docker run ... cybersec-slm cybersec-slm extract all`.
See **[docs/deploy.md](docs/deploy.md)** for the AWS (ECR / ECS / Prefect) path.

## Project layout

```
src/cybersec_slm/
  core.py        shared bits: logging, data paths, JSONL + hashing
  cli.py         single entry point (source / extract / clean / eda / normalize / run / flow / all)
  sourcing/      search-engine source discovery → tracking sheet
  extraction/    fetch, scrape, crawl, allowlist gate, parallel worker
  cleaning/      sanitize, anomaly, dedup, pii, langfilter, translate, pipeline
  eda/           metrics + sufficiency gate
  normalize/     schema, mappers, enrich, dedup, manifest → final_data/dataset.jsonl
  orchestration/ Prefect build-corpus flow
tests/           pytest suite for every stage
sources/         allowlist.yaml + the research behind it
docs/            architecture, schema, deployment, security notes
infra/           Terraform skeleton (ECR / ECS / S3 / IAM / Secrets Manager)
```

Generated data lives at the project root and stays out of git: `raw_data/`
(extraction), `clean_data/` (cleaning → EDA handoff), `flagged/` (records a human
should look at), `dropped/` (removed, with reasons), `final_data/` (the release),
and `logs/`.

## Configuration

The pipeline reads optional API keys from a `.env` file (auto-loaded at startup;
shell environment variables take precedence). None are required for a basic local
run.

| Variable | Used by | Required? |
|---|---|---|
| `NVD_API_KEY` | `extract nvd` (higher CVE rate limit) | optional |
| `KAGGLE_API_TOKEN` | Kaggle sources | only for kaggle sources |
| `GOOGLE_SEARCH_API_KEY`, `GOOGLE_SEARCH_ENGINE_ID` | `source` | only for sourcing |
| `GOOGLE_SHEETS_CREDENTIALS` | `source` (appending to the sheet) | only for live append |
| `CYBERSEC_SLM_DATA_ROOT` | all stages (where data is written) | optional |
| `CYBERSEC_SLM_ENFORCE_ALLOWLIST` | extraction allowlist gate | optional |

## Optional extras

```bash
uv sync --extra orchestration   # Prefect + prefect-aws (for `flow` and the AWS deployment)
```

- **orchestration** powers `cybersec-slm flow` and the ECS deployment.
  `cybersec-slm all` runs the identical pipeline locally without it. It pulls in
  ~100 packages, and on Windows its `whenever` extension ships a DLL that Smart
  App Control may block — so it is opt-in.
- **profiling** (`ydata-profiling`, the optional `eda --profile` HTML report) pins
  pandas `<3.0`, which conflicts with the pipeline's pandas `>=3.0`. The EDA gate
  runs without it; for a one-off profile, use a throwaway env:
  `uvx --with 'pandas<3' ydata-profiling`.

Every cleaning tool also has a standard-library fallback and logs which backend it
used, so a missing optional dependency degrades quality gracefully instead of
failing the run.

## Development

```bash
uv run pytest                  # full test suite
uv run ruff check src tests    # lint
```

## Documentation

| Doc | What's in it |
|---|---|
| [architecture.md](docs/architecture.md) | How the pipeline works, stage by stage, with the data flow and security controls |
| [canonical_schema.md](docs/canonical_schema.md) | The canonical 22-field record schema (the downstream handoff contract) |
| [deploy.md](docs/deploy.md) | AWS deployment (Prefect Cloud + ECS Fargate, ECR, S3) |
| [dvc.md](docs/dvc.md) | Versioned corpus releases with DVC + S3 |
| [pii_limitations.md](docs/pii_limitations.md) | What the automated PII pass does and does not catch |
| [risk_register.md](docs/risk_register.md) | Operational risks and mitigations |
| `docs/source_*.md` | How sources were researched, evaluated, and accepted |

## Security

Each stage assumes its input could be hostile or low quality and responds in a way
that stays traceable and reversible: an allowlist before any fetch, PII redaction
and anomaly flagging during cleaning, a blocking sufficiency gate at EDA, strict
schema validation with per-source failure escalation at normalization, and a
content-hashed provenance manifest at release. CI adds secret scanning (gitleaks)
and dependency auditing (pip-audit). The details are in
[docs/architecture.md](docs/architecture.md#security-controls) and
[docs/pii_limitations.md](docs/pii_limitations.md).

## Status

All five stages are implemented, wired end to end, and covered by the test suite.
The current focus is the security baseline (source allowlist, secret and
supply-chain scanning, metadata-only reject logs, provenance manifest) and the
automated Prefect + DVC deployment on AWS.
