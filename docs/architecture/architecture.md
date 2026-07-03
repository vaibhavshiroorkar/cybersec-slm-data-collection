# Architecture

How the pipeline works, end to end. This is the companion to the
[README](../../README.md): the README tells you how to run it; this document
explains what happens inside.

## Overview

The pipeline turns scattered cybersecurity text into a single clean,
schema-standardized, training-ready corpus (`data/final/dataset.jsonl`) plus a
provenance manifest. It is an installable package (`cybersec_slm`) driven by one
CLI (`src/cybersec_slm/cli.py`).

```
Sourcing  →  Ingestion   →  Cleaning   →  EDA gate  →  Normalization  →  dataset.jsonl
(optional)    data/raw/     data/clean/   (pass?)       data/final/        + manifest.json
```

Two ideas shape everything:

- **Everything resolves around a data root.** `core.py` defines the working
  folders relative to `CYBERSEC_SLM_DATA_ROOT` (falling back to the current
  directory). Every generated corpus artifact lives under a single `data/` folder
  (`data/raw/`, `data/clean/`, `data/final/`, `data/flagged/`, `data/dropped/`),
  with run logs in `logs/` alongside it. These are generated and git-ignored, so the
  repository stays code-only. `core.py` also holds the shared logger and the JSONL
  read/write and hashing helpers used by every stage.
- **Security is part of the flow, not a layer on top.** A version-controlled
  source allowlist gates ingestion; reject logs are metadata-only; every release
  ships a content-hashed manifest so a bad batch can be scoped and rolled back.
  See [Security controls](#security-controls).

## One run mode: parallel streaming

Ingestion and cleaning are fused and run in parallel. `cybersec-slm run` and
`cybersec-slm all` both drive `ingestion/parallel.py::run_streaming`; the Prefect
`flow` wraps the same per-source function. One worker process per source does
fetch → clean → delete raw (`ingestion/worker.py`), sources are isolated (a bad one
returns `status="failed"` instead of crashing the pool), and after the pool drains a
single cross-source dedup pass runs over `data/clean/`. `run` stops there; `all` and
`flow` continue into the EDA gate and normalizer.

**Resumable, cheap re-runs.** `--resume` skips sources already fetched+cleaned in a
prior run (recorded per-source in `logs/completed_sources.txt`, keyed by the
allowlist `descriptor_key`) and picks the final dedup pass back up where it stopped,
so an interrupted build never re-downloads multi-GB sources. A fresh run (the
default) resets that ledger and the dedup checkpoint so nothing is silently skipped.
Failed sources are never recorded, so they retry on the next run.

## Stage 0: Sourcing *(optional)*

`cybersec-slm source` (`sourcing/run.py`) proposes new candidate sources. For each
cybersecurity sub-domain it runs keyword searches through Google Programmable
Search, builds a candidate row per hit, drops any URL already in the catalog
(or seen earlier in the run), writes the survivors to a CSV under
`logs/discovered/`, and, unless `--dry-run`, appends them to the local catalog
(`sources/Sources.csv`).

This stage only *proposes* sources for a human to review. Nothing here reaches
ingestion directly; the gate between "discovered" and "fetched" is the allowlist.

## Stage 1: Ingestion → `data/raw/`

Ingestion (`ingestion/parallel.py`, driven by `cybersec-slm run` / `all`) pulls
each source through its handler and normalizes everything to JSONL:

- **fetch**: dataset platforms (HuggingFace, Kaggle, raw URLs, GitHub)
- **scrape**: PDFs and JSON feeds
- **html**: a few crawlable sites (Playwright/Chromium)
- **nvd**: the NVD CVE feed (optional API key for higher rate limits)

The **source allowlist** (`ingestion/allowlist.py`) is the key control here. Only
sources marked `status: approved` in `sources/allowlist.yaml` are fetched;
everything else is skipped and logged. This is the anti-poisoning gate: a
substituted or compromised upstream cannot enter the corpus under a trusted name.
It fails open (allow-all, with a warning) when the file is absent so a fresh
checkout still runs, and `CYBERSEC_SLM_ENFORCE_ALLOWLIST=1` forces enforcement
(the Docker image sets this).

A second gate, the **license gate** (`ingestion/license_gate.py`), runs
immediately after the allowlist in the worker: a source is fetched only if its
`Sources.csv` license clearly permits unencumbered commercial use. It is
**default-deny** — copyleft (GPL/LGPL), share-alike / non-commercial Creative
Commons (`-SA` / `-NC`), and any license string it doesn't recognise as clearly
commercial are skipped with a `license: …` reason, distinct from the allowlist's
`allowlist: …` skip. This keeps legally-unusable data out of a commercially-trained
corpus without depending on the manual license triage having been applied
consistently before a source was approved. `CYBERSEC_SLM_ENFORCE_LICENSE_GATE=0`
disables it for local runs.

Ingestion maintains a SQLite ingest log, a provenance ledger
(`logs/provenance/ledger.csv`), and a summary table of every source's size, row
count, and license. `ingestion/worker.py` handles one source per process; a bad
source returns `status="failed"` instead of crashing the pool. The parent also
appends each completed source to `logs/completed_sources.txt`, the ledger that
`--resume` reads to skip already-finished work.

## Stage 2: Cleaning → `data/clean/` (+ `data/flagged/`, `data/dropped/`)

Cleaning (`cleaning/pipeline.py`, run per source inside the worker) runs each
record through a fixed order:

1. **Text mapping**: build a `text` field from prose columns; feature-table rows
   with no prose are excluded from the text corpus.
2. **Anomaly classification + sanitize**: structural problems → `data/dropped/`;
   behavioral anomalies → `data/flagged/` for human review; sanitize can rescue a
   record.
3. **Dedup**: exact and near-duplicate detection; duplicates → `data/dropped/`.
4. **PII redaction**: Presidio (with a regex fallback) redacts PII in place.
5. **Language**: non-English text is translated into English and kept; only
   untranslatable text is dropped.

Survivors land in `data/clean/`, mirroring the `data/raw/` layout. Drops and flags
are annotated with `_stage` and `_reason`, and a per-file report is written to
`logs/clean_report.csv`. Every step degrades gracefully: if an optional tool is
missing it falls back to a standard-library heuristic and logs which backend it
used.

Per-source workers run with dedup disabled; after the pool drains,
`final_global_dedup()` makes one pass over `data/clean/` to catch duplicates shared
across sources. That pass is deterministic (files processed in sorted order, so
which of two cross-source duplicates survives is stable) and checkpointed: the
exact-hash set (`logs/dedup_checkpoint.json`) and the list of finished files
(`logs/dedup_done.json`) are written after each file, so `--resume` restarts an
interrupted dedup where it stopped instead of from zero.

## Stage 3: EDA sufficiency gate → `logs/eda/`

`cybersec-slm eda` (`eda/pipeline.py`) turns analysis into an enforcement point:

1. Compute metrics over `data/clean/`: volume, per-subdomain balance, source
   concentration, text quality, duplicate rate.
2. Compute drift versus the previous run (max change in subdomain distribution).
3. Evaluate the gate against thresholds in `eda/config.py` (all env-overridable).
   Violations are **blocker** or **warning**:
   - *blockers*: too few total records, or one source dominating a subdomain
     (concentration ceiling).
   - *warnings*: thin subdomains, high duplicate rate, low average tokens, drift.
4. Persist a versioned `logs/eda/run-<ts>.json` (append-only history) plus
   `latest.json`.

A blocker raises `SufficiencyError`, which halts the pipeline so you loop back to
ingestion instead of advancing. Warnings are logged and tracked but do not stop the
run. `--no-enforce` makes it report-only.

## Stage 4: Normalization → `data/final/dataset.jsonl`

`cybersec-slm normalize` (`normalize/pipeline.py`) maps every surviving record onto
the canonical 22-field schema and produces the release. Each record flows through:

1. **Source mapper + registry dispatch** (`normalize/mappers.py`): a `ProseMapper`
   for natural-language records, a `StructuredMapper` that renders table rows into
   readable "key: value" sentences. Unknown sources dispatch by record shape and
   raise a first-sight alert.
2. **Enrichment** (`normalize/enrich.py`): fills everything the mapper can't: a
   uuid4 `id`, the `content_hash`, auto-computed `lang` / `token_count` /
   `char_count`, pipeline version and timestamp, the resolved `domain_name` /
   `subdomain_name`, and placeholders for downstream-owned fields (snorkel labels →
   `-1` ABSTAIN; human-annotation fields → `null`).
3. **Validation** against `CanonicalRecord` (`normalize/schema.py`, Pydantic with
   `extra="forbid"` and closed enums). Invalid records go to **metadata-only**
   `rejected.jsonl`; raw text is gated behind `CYBERSEC_SLM_DEBUG_REJECTS=1`. A
   `FailureTracker` counts rejects per source, warns at 5, and hard-pauses a source
   at 20.
4. **Near-duplicate check** (`normalize/dedup.py`): MinHash/LSH at Jaccard 0.65,
   with every record's best-match score logged to `dedup_scores.jsonl`. Duplicates
   go to `duplicates.jsonl`.
5. **Output**: survivors are appended to `dataset.jsonl` and the hash index is
   updated. State is rebuilt from any existing `dataset.jsonl`, so runs are
   resumable.

Finally, the run writes the **provenance manifest** (`normalize/manifest.py`), a
"datasheet for datasets": record counts by domain / source / license / format /
language, the EDA snapshot, pipeline version, git commit, and a sha256 of the
dataset file. See [canonical_schema.md](canonical_schema.md) for the field-by-field
contract.

## Orchestration, versioning, deployment

- **Prefect** (`orchestration/flows.py`): `cybersec-slm flow` wraps the same stage
  functions in a `build-corpus` flow: load secrets → ingest + clean per source
  (mapped, retried, isolated) → cross-source dedup → EDA gate → normalize →
  optional DVC snapshot. Prefect is optional; the decorators degrade to no-ops so
  the helpers stay unit-testable.
- **DVC** (`dvc.yaml`): `dvc repro` rebuilds the corpus and versions the outputs
  to an S3 remote, with the EDA and normalize reports tracked as metrics. See
  [dvc.md](../operations/dvc.md).
- **AWS**: Dockerized, with a Terraform skeleton (ECR / ECS / S3 / IAM / Secrets
  Manager) and CI/CD. See [deploy.md](../operations/deploy.md).

## Security controls

Each stage assumes its input could be hostile or low quality and pushes the
response toward something traceable, reversible, and auditable.

| Stage | Controls |
|---|---|
| Sourcing | Discovered sources seeded `pending` (human review before fetch); dry-run + CSV audit artifact |
| Ingestion | Version-controlled source allowlist (anti-poisoning); default-deny commercial-license gate; per-source process isolation; provenance ingest ledger |
| Cleaning | PII redaction (Presidio + regex fallback); documented PII blind spots + sampled manual review; anomaly quarantine to `flagged/`; auditable `dropped/` reasons |
| EDA | Blocking sufficiency gate; source-concentration ceiling; drift detection; versioned append-only run history |
| Normalization | Strict schema validation (closed enums); metadata-only reject logs; per-source failure escalation; per-record near-dup scores; content hashing |
| Release | Provenance manifest (datasheet); DVC-versioned releases for scoped rollback |
| CI / supply chain | Secret scanning (gitleaks, full history); dependency audit (pip-audit); least-privilege CI token |
| Deployment | ECR immutable tags + scan-on-push; S3 public-access block + SSE + versioning; least-privilege IAM task role; secrets injected at runtime, never baked in |

PII redaction has known limits on a security corpus (internal hostnames, private
IPs, service accounts, API keys); these are documented with a manual-review process
in [pii_limitations.md](../pii_limitations.md).

## Data layout

All generated corpus artifacts live under one `data/` folder, with run logs in
`logs/` alongside it:

| Folder | Produced by | Purpose |
|---|---|---|
| `data/raw/` | ingestion | normalized JSONL per source |
| `data/clean/` | cleaning | the cleaned corpus → EDA handoff |
| `data/flagged/` | cleaning | behavioral anomalies for human review |
| `data/dropped/` | cleaning / dedup | removed records, each with a `_reason` |
| `data/final/` | normalization | `dataset.jsonl` + `manifest.json` + reject/dup sinks |
| `logs/` | all stages | run logs, EDA history, clean/normalize reports, provenance ledger |

Both `data/` and `logs/` are resolved relative to `CYBERSEC_SLM_DATA_ROOT`
(default: current directory) and are git-ignored.

## Configuration

Optional API keys are read from `.env` (auto-loaded; shell environment wins). See
the [README configuration table](../../README.md#configuration) for the full list.
EDA gate thresholds and the allowlist enforcement flag are environment-overridable;
see `eda/config.py` and `ingestion/allowlist.py`.
