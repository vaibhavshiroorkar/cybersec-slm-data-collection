# Cybersecurity SLM Data Pipeline

A reproducible pipeline that gathers cybersecurity text from across the web and
turns it into a clean, schema-standardized, training-ready corpus for a small
language model (SLM).

The pipeline runs as five stages that can be invoked individually or end to end:

| Stage | What it does | Output |
|---|---|---|
| **Sourcing** *(optional)* | Searches the web by keyword and compiles a reviewed tracking sheet of candidate sources | tracking sheet + `logs/discovered/` |
| **Extraction** | Pulls each *allowlisted* source (datasets, PDFs, feeds, crawlable sites) and normalizes it to JSONL | `raw_data/` |
| **Cleaning** | Sanitizes text, flags anomalies, drops duplicates, redacts PII, and translates non-English content into English | `clean_data/`, `flagged/`, `dropped/` |
| **EDA** | Validates the corpus (volume, balance, concentration, drift, duplicates) behind a sufficiency gate | `logs/eda/` |
| **Normalization** | Maps every record onto the canonical 22-field schema, hashes it, removes near-duplicates, and writes a provenance manifest | `final_data/dataset.jsonl` + `manifest.json` |

It ships as an installable Python package (`cybersec_slm`) with a single CLI.
Security is built into every stage — a version-controlled source allowlist, PII
redaction, metadata-only reject logs, content hashing, and a provenance manifest —
and an optional Prefect + DVC layer runs the whole pipeline on AWS.

For a complete walk-through of how it works, see **[docs/architecture/architecture.md](docs/architecture/architecture.md)**.

## Quickstart

Requires Python 3.13+ and [uv](https://docs.astral.sh/uv/).

```bash
cp .env.example .env                    # add API keys (all optional for a basic run)
uv sync                                 # installs the pipeline and dev tools
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

Output folders are created at the project root and are git-ignored. Redirect them
with `CYBERSEC_SLM_DATA_ROOT`. If you would rather not use the console script,
`python -m cybersec_slm <command> ...` works the same way.

### Commands at a glance

| Command | Purpose |
|---|---|
| `extract [scrape\|fetch\|html\|nvd\|all\|table]` | Fetch and normalize allowlisted sources |
| `clean [all\|sanitize\|dedup\|pii\|lang\|report\|balance]` | Clean the raw corpus |
| `eda [--no-enforce] [--profile]` | Validate the corpus and apply the sufficiency gate |
| `normalize [--fresh]` | Schema-normalize into `dataset.jsonl` + manifest |
| `run [--workers N]` | Parallel per-source fetch and clean (streaming) |
| `source [--dry-run]` | Discover sources via search engines → tracking sheet |
| `flow [--dvc-push]` | Run the pipeline via Prefect (needs the `orchestration` extra) |
| `validate` | Check `clean_data/` records against the schema |
| `all` | Run the full pipeline, end to end |

## Docker

```bash
docker build -t cybersec-slm .
docker run --rm --env-file .env -v "$(pwd)/data:/data" cybersec-slm
```

On Windows PowerShell, mount the volume with `-v "${PWD}\data:/data"`. The image
runs as a non-root user, writes outputs to the mounted `/data` volume, and reads
secrets at runtime (they are never baked into the image). To run a single stage,
append it after the image name, e.g.
`docker run ... cybersec-slm cybersec-slm extract all`. See
**[docs/operations/deploy.md](docs/operations/deploy.md)** for the AWS (ECR / ECS / Prefect) path.

## Project layout

```
src/cybersec_slm/
  core.py        shared utilities: logging, data paths, JSONL + hashing
  cli.py         single entry point (source / extract / clean / eda / normalize / run / flow / all)
  sourcing/      search-engine source discovery → tracking sheet
  extraction/    fetch, scrape, crawl, allowlist gate, parallel worker
  cleaning/      sanitize, anomaly, dedup, pii, langfilter, translate, pipeline
  eda/           metrics + sufficiency gate
  normalize/     schema, mappers, enrich, dedup, manifest → final_data/dataset.jsonl
  orchestration/ Prefect build-corpus flow
tests/           pytest suite covering every stage
sources/         allowlist.yaml + the research behind it
docs/            architecture, schema, deployment, and security notes
infra/           Terraform skeleton (ECR / ECS / S3 / IAM / Secrets Manager)
```

Generated data lives at the project root and stays out of git: `raw_data/`
(extraction), `clean_data/` (the cleaning → EDA handoff), `flagged/` (records a
human should review), `dropped/` (removed records, with reasons), `final_data/`
(the release), and `logs/`.

## Configuration

The pipeline reads optional API keys from a `.env` file, auto-loaded at startup;
shell environment variables take precedence. None are required for a basic local
run.

| Variable | Used by | Required? |
|---|---|---|
| `NVD_API_KEY` | `extract nvd` (higher CVE rate limit) | optional |
| `KAGGLE_API_TOKEN` | Kaggle sources | only for Kaggle sources |
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
  roughly 100 packages, and on Windows its `whenever` extension ships a DLL that
  Smart App Control may block — so it is opt-in.
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

## Documentation

| Doc | What's in it |
|---|---|
| [architecture.md](docs/architecture/architecture.md) | How the pipeline works, stage by stage, with the data flow and security controls |
| [canonical_schema.md](docs/architecture/canonical_schema.md) | The canonical 22-field record schema (the downstream handoff contract) |
| [deploy.md](docs/operations/deploy.md) | AWS deployment (Prefect Cloud + ECS Fargate, ECR, S3) |
| [dvc.md](docs/operations/dvc.md) | Versioned corpus releases with DVC + S3 |
| [pii_limitations.md](docs/pii_limitations.md) | What the automated PII pass does and does not catch |
| [risk_register.md](docs/risk_register.md) | Operational risks and mitigations |
| `docs/sources/source_*.md` | How sources were researched, evaluated, and accepted |

## Security

Each stage assumes its input could be hostile or low quality and responds in a way
that stays traceable and reversible: an allowlist before any fetch, PII redaction
and anomaly flagging during cleaning, a blocking sufficiency gate at EDA, strict
schema validation with per-source failure escalation at normalization, and a
content-hashed provenance manifest at release. CI adds secret scanning (gitleaks)
and dependency auditing (pip-audit). The details are in
[docs/architecture/architecture.md](docs/architecture/architecture.md#security-controls) and
[docs/pii_limitations.md](docs/pii_limitations.md).

## Project status

**Week 4 — orchestration and deployment.**

All five stages are implemented, wired end to end, and covered by the test suite.
With the pipeline feature-complete, the focus has shifted to operations: hardening
the security baseline (source allowlist, secret and supply-chain scanning,
metadata-only reject logs, provenance manifest) and standing up the automated
Prefect + DVC deployment on AWS for scheduled, versioned corpus releases.
