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

- **Two gates before a fetch.** A source is pulled only if it's marked `approved` in
  `sources/allowlist.yaml` — so a swapped-out or compromised upstream can't sneak into
  the corpus under a trusted name — *and* its license clearly allows commercial use.
  Anything else is skipped and logged.
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
uv run cybersec-slm all --resume        # re-run without re-downloading finished sources
```

That writes the finished corpus to `data/final/dataset.jsonl`. To watch a run live,
browse the result, and ask a built-in Q&A agent about the corpus — all in the browser:

```bash
uv sync --extra dashboard               # installs Streamlit (opt-in extra)
uv run cybersec-slm dashboard           # -> http://localhost:8501
```

To run the stages individually, tune them with flags, or deploy with Docker, see
**[docs/commands.md](docs/commands.md)**, the full command reference.

> Output folders (`data/`, `logs/`) are created at the project root and are
> git-ignored. Point them somewhere else with `CYBERSEC_SLM_DATA_ROOT`.

## Project layout

```
src/cybersec_slm/
  core.py        shared utilities: logging, data paths, JSONL + hashing
  cli.py         the single entry point (source / run / clean / eda / normalize / flow / dashboard / all)
  sourcing/      search-engine source discovery → Sources.csv catalog
  ingestion/     fetch, scrape, crawl, allowlist + license gate, parallel worker
  cleaning/      sanitize, anomaly, dedup, pii, langfilter, translate
  eda/           metrics + the sufficiency gate
  normalize/     schema, mappers, enrich, dedup, manifest → data/final/dataset.jsonl
  orchestration/ Prefect build-corpus flow
  dashboard/     read-only Streamlit monitor + dataset explorer + Q&A agent
sources/         Sources.csv (the curated catalog) + allowlist.yaml + the research behind them
tests/           pytest suite covering every stage
docs/            architecture, commands, schema, deployment, and security notes
infra/           Terraform skeleton (ECR / ECS / S3 / IAM / Secrets Manager)
```

## Security

Security isn't a layer bolted on at the end — it's part of how each stage behaves, and
the design consistently favors choices that are traceable, reversible, and auditable.
Beyond the ingestion gates and the provenance manifest described above, CI scans the
full git history for secrets (gitleaks) and audits dependencies (pip-audit). The full
reasoning is in
[architecture.md](docs/architecture/architecture.md#security-controls), and the honest
limits of automated PII redaction on a security corpus are documented in
[pii_limitations.md](docs/pii_limitations.md).

## Documentation

| Doc | What's in it |
|---|---|
| [commands.md](docs/commands.md) | Every command, flag, and run mode; Docker; configuration; development |
| [pipeline-flow.md](docs/pipeline-flow.md) | Following the data: a plain-language walk of what happens to a record from catalog to finished dataset |
| [architecture/architecture.md](docs/architecture/architecture.md) | How the pipeline works, stage by stage, with the data flow and security controls |
| [architecture/canonical_schema.md](docs/architecture/canonical_schema.md) | The canonical 22-field record schema (the downstream handoff contract) |
| [operations/deploy.md](docs/operations/deploy.md) | AWS deployment (Prefect Cloud + ECS Fargate, ECR, S3) |
| [operations/dvc.md](docs/operations/dvc.md) | Versioned corpus releases with DVC + S3 |
| [pii_limitations.md](docs/pii_limitations.md) | What the automated PII pass does and does not catch |
| [risk_register.md](docs/risk_register.md) | Operational risks and mitigations |
| `docs/sources/source_*.md` | How sources were researched, evaluated, and accepted |
| [dashboard/README.md](src/cybersec_slm/dashboard/README.md) | The Streamlit dashboard: pages, what each one shows, how it reads data |

## Project status

**v1 — complete.** Week 4 (orchestration and deployment) is done, and with it the whole
v1 pipeline. All five stages are built, wired end to end, and covered by the test suite,
and the operational layer around them is in place: ingestion sits behind two gates (the
source allowlist and a default-deny commercial-license gate), releases are
content-hashed into a provenance manifest and can be versioned and shipped through
Prefect + DVC on AWS, and a read-only Streamlit dashboard adds live run monitoring, a
dataset explorer, and a natural-language Q&A agent over the corpus.

From here the work is incremental: adding vetted sources, widening PII coverage, and
tuning the sufficiency thresholds as the corpus grows.
