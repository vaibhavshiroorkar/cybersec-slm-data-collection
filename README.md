# Cybersecurity SLM Data Pipeline

This project builds the training data for a small cybersecurity language model.

There's no shortage of good cybersecurity material on the internet: CVE feeds, NIST
publications, MITRE catalogs, research datasets, security blogs. The problem is that
it's scattered across dozens of formats and sites, tangled up with noise, duplicates,
and personal data, and none of it arrives in the shape a model wants to read. This
pipeline handles that unglamorous middle work. It gathers the good material from a
vetted list of sources and turns it into one clean, consistent, training-ready corpus
you can trust and trace.

It ships as an installable Python package (`cybersec_slm`) driven by a single command,
`cybersec-slm`. Run the whole thing end to end, or one stage at a time.

## How it works

The work happens in five stages. Each one hands its output to the next, and each one
treats its input as possibly messy or untrustworthy, so problems get flagged, dropped,
or quarantined instead of slipping downstream unnoticed.

| Stage | In plain terms | Output |
|---|---|---|
| **Sourcing** *(optional)* | Goes looking for new sources by searching the web and adds the candidates to a tracking catalog for a human to review. Nothing here is trusted automatically. | `sources/Sources.csv` |
| **Ingestion** | Downloads each *approved* source (datasets, PDFs, feeds, crawlable sites) and converts everything to one simple line-per-record format. | `data/raw/` |
| **Cleaning** | Tidies the text, flags suspicious records, removes duplicates, redacts personal data, and translates non-English text into English. | `data/clean/` (plus `flagged/`, `dropped/`) |
| **EDA gate** | Checks whether the corpus is actually good enough: enough volume, balanced across topics, not dominated by any single source. If it isn't, the run stops here. | `logs/eda/` |
| **Normalization** | Maps every record onto one canonical 22-field schema, removes near-duplicates, and writes the final dataset alongside a provenance manifest. | `data/final/dataset.jsonl` |

A few ideas hold it together:

- **One vetted source list.** A source only gets fetched if it's marked `approved` in
  `sources/allowlist.yaml`, so a compromised or swapped-out upstream can't sneak into
  the corpus under a trusted name.
- **Nothing is thrown away quietly.** Removed records go to `data/dropped/` with a
  reason, and records that need a human eye go to `data/flagged/`. Everything stays
  auditable.
- **Every release is traceable.** The final dataset ships with a content-hashed
  manifest, a kind of "datasheet" that records where each record came from, under what
  license, and from which pipeline version. That is what lets a bad batch be scoped and
  rolled back.

For the full stage-by-stage walk-through, see
**[docs/architecture/architecture.md](docs/architecture/architecture.md)**.

## Quickstart

Requires Python 3.13+ and [uv](https://docs.astral.sh/uv/).

```bash
cp .env.example .env                    # API keys (all optional for a basic run)
uv sync                                 # install the pipeline
uv run cybersec-slm all                 # ingest → clean → EDA gate → normalize
```

That writes the finished corpus to `data/final/dataset.jsonl`. To run the stages
individually, tune them with flags, or deploy with Docker, see
**[docs/commands.md](docs/commands.md)**, the full command reference.

> Output folders (`data/`, `logs/`) are created at the project root and are
> git-ignored. Point them somewhere else with `CYBERSEC_SLM_DATA_ROOT`.

## Project layout

```
src/cybersec_slm/
  core.py        shared utilities: logging, data paths, JSONL + hashing
  cli.py         the single entry point (source / run / clean / eda / normalize / flow / all)
  sourcing/      search-engine source discovery → Sources.csv catalog
  ingestion/     fetch, scrape, crawl, allowlist gate, parallel worker
  cleaning/      sanitize, anomaly, dedup, pii, langfilter, translate
  eda/           metrics + the sufficiency gate
  normalize/     schema, mappers, enrich, dedup, manifest → data/final/dataset.jsonl
  orchestration/ Prefect build-corpus flow
sources/         Sources.csv (the curated catalog) + allowlist.yaml + the research behind them
tests/           pytest suite covering every stage
docs/            architecture, commands, schema, deployment, and security notes
infra/           Terraform skeleton (ECR / ECS / S3 / IAM / Secrets Manager)
```

Generated data stays out of git and lives under one `data/` folder: `data/raw/`
(ingestion), `data/clean/` (the cleaning → EDA handoff), `data/flagged/` (records a
human should review), `data/dropped/` (removed records, with reasons), and
`data/final/` (the release). Run logs go to `logs/`.

## Security

Security isn't a layer bolted on at the end. It's part of how each stage behaves. An
allowlist gates every fetch, PII is redacted and anomalies quarantined during cleaning,
a blocking sufficiency gate sits between cleaning and release, normalization validates
against a strict schema with per-source failure limits, and every release is
content-hashed into a provenance manifest. CI adds secret scanning (gitleaks) and
dependency auditing (pip-audit). The reasoning is in
[architecture.md](docs/architecture/architecture.md#security-controls), and the known
limits of automated PII redaction on a security corpus are documented honestly in
[pii_limitations.md](docs/pii_limitations.md).

## Documentation

| Doc | What's in it |
|---|---|
| [commands.md](docs/commands.md) | Every command, flag, and run mode; Docker; configuration; development |
| [architecture/architecture.md](docs/architecture/architecture.md) | How the pipeline works, stage by stage, with the data flow and security controls |
| [architecture/canonical_schema.md](docs/architecture/canonical_schema.md) | The canonical 22-field record schema (the downstream handoff contract) |
| [operations/deploy.md](docs/operations/deploy.md) | AWS deployment (Prefect Cloud + ECS Fargate, ECR, S3) |
| [operations/dvc.md](docs/operations/dvc.md) | Versioned corpus releases with DVC + S3 |
| [pii_limitations.md](docs/pii_limitations.md) | What the automated PII pass does and does not catch |
| [risk_register.md](docs/risk_register.md) | Operational risks and mitigations |
| `docs/sources/source_*.md` | How sources were researched, evaluated, and accepted |

## Project status

**Week 4: orchestration and deployment.** All five stages are implemented, wired end to
end, and covered by the test suite. With the pipeline feature-complete, the focus has
shifted to operations: hardening the security baseline and standing up the automated
Prefect + DVC deployment on AWS for scheduled, versioned corpus releases.
