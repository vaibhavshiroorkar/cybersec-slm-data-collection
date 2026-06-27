# Cybersecurity SLM Data Pipeline

This project gathers cybersecurity text from across the web and turns it into a
clean, schema-standardized, training-ready corpus for a small language model.
The full pipeline runs in stages you can invoke on their own or back to back:

- **Discovery** *(optional)* — search engines by keyword → a tracking sheet of
  candidate sources.
- **Extraction** — pull data from each *allowlisted* source (datasets, PDFs,
  feeds, a few crawlable sites) and normalize everything to JSONL.
- **Cleaning** — sanitize, check for anomalies, drop duplicates, strip PII, and
  normalize the language to English (translating non-English text rather than
  dropping it).
- **EDA** — validate the cleaned corpus (volume, balance, concentration, drift,
  duplicates) behind a *sufficiency gate*: pass → normalize; blocker → loop back.
- **Normalization** — map every record onto the canonical 22-field schema
  (`normalized/dataset.jsonl`), with content hashing, near-dup detection, and a
  provenance manifest for the downstream labeling/annotation teams.

It's packaged as a proper installable package (`cybersec_slm`) with a single CLI.
Security controls (source allowlist, secret/supply-chain scanning, metadata-only
reject logs, versioned provenance) and an automated Prefect + DVC deployment on
AWS layer on top — see `docs/deploy.md` and `docs/dvc.md`.

## How it's laid out

```
src/cybersec_slm/
  core.py        shared bits: logging, data paths, JSONL + hashing
  cli.py         one entry point — discover / extract / clean / eda / normalize / all / flow
  discovery/     search.py, sheet.py, classify.py (search-engine source discovery)
  extraction/    fetch, scrape, scrape_html, manifest, sources, allowlist, worker, parallel
  cleaning/      sanitize, anomaly, dedup, pii, langfilter, translate, pipeline
  eda/           metrics + sufficiency gate (config.py, metrics.py, pipeline.py)
  normalize/     schema, mappers, enrich, dedup, manifest, pipeline (-> dataset.jsonl)
  orchestration/ flows.py (Prefect build-corpus flow)
tests/           pytest suite for every stage
sources/         allowlist.yaml + the research behind which sources made the cut
docs/            schema, deploy, dvc, pii_limitations, risk register, source notes
infra/           Terraform skeleton (ECR / ECS / S3 / IAM / Secrets Manager)
```

The pipeline writes its data into folders at the project root — `raw_data/`
(extraction output), `cleaned/` (the handoff for EDA), `flagged/` (records a
human should look at), `dropped/` (what got removed, with reasons), and `logs/`.
These are all generated and git-ignored, so the repo stays code-only.

## Getting set up

```bash
cp .env.example .env
uv venv && source .venv/bin/activate
uv sync                       # everything extraction needs
uv sync --extra cleaning      # optional — see the note below
uv sync --extra dev           # optional — pytest + ruff
```

A nice property of the cleaning stage: it runs on the standard library alone.
The heavy tools (Presidio for PII, fastText for language ID, datasketch for
near-duplicates) are optional — if they're not installed, each step quietly
falls back to a built-in (regex, a stopword/script heuristic, a pure-Python
MinHash). Installing the `cleaning` extra just upgrades the quality. Each run
logs which backend it actually used.

## Running it

By default the pipeline reads and writes in your current directory; point it
somewhere else with the `CYBERSEC_SLM_DATA_ROOT` environment variable.

```bash
cybersec-slm extract all      # collect allowlisted sources into raw_data/
cybersec-slm clean all        # raw_data/ -> cleaned/, flagged/, dropped/, + a report
cybersec-slm eda              # validate the cleaned corpus + sufficiency gate
cybersec-slm normalize        # cleaned records -> normalized/dataset.jsonl (+ manifest)
cybersec-slm all              # extract -> clean -> eda gate -> normalize, in order
cybersec-slm flow             # the same end to end via Prefect (needs the orchestration extra)
```

`extract` also takes `scrape`, `fetch`, `html`, `nvd`, or `table`; `clean` takes
the individual stage names plus `report`/`balance`. Source fetching is gated by
`sources/allowlist.yaml` — only `status: approved` sources are pulled. If you'd
rather not install the console script, `python -m cybersec_slm <stage> ...` works too.

## Working on it

```bash
pytest                 # run the tests
ruff check src tests   # lint
```

## Where things stand

- **Week 1** — researched the sources, checked licensing, settled on a shortlist.
- **Week 2** — built the extraction and cleaning stages and packaged it up
  (src layout, a real CLI, tests for both stages).
- **Now** — added the EDA sufficiency gate, the canonical 22-field schema +
  normalization, a security baseline (source allowlist, secret/supply-chain
  scanning, CI, metadata-only reject logs, provenance manifest), and an automated
  Prefect + DVC deployment on AWS (`docs/deploy.md`, `docs/dvc.md`).
