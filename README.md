# Cybersecurity SLM Data Pipeline

Training data for a small cybersecurity language model.

Good cybersecurity material is everywhere — CVE feeds, NIST publications, MITRE
catalogs, research datasets, security writeups — but it is scattered across
formats and sites, tangled with noise, duplicates and personal data, and none of
it arrives in the shape a model wants to read. This pipeline does that unglamorous
middle work: it gathers the good material, cleans it, and turns it into one
consistent, training-ready corpus you can trace back to its sources.

It installs as a Python package (`cybersec_slm`) and runs from one command,
`cybersec-slm` — the whole pipeline end to end, or a stage at a time.

## How it works

Five stages, each handing its output to the next, each treating its input as
possibly messy or hostile — so problems are flagged, dropped or quarantined
rather than slipping downstream.

| Stage | What it does | Output |
|---|---|---|
| **Sourcing** *(optional)* | Searches the web through a self-hosted [SearXNG](https://docs.searxng.org/) instance and adds candidate sources to a catalog for review. Keywords, feeds and links are editable per topic. Nothing is trusted automatically. | `sources/profiles/<name>/Sources.csv` |
| **Ingestion** | Fetches each source (datasets, PDFs, RSS/Atom feeds, crawlable sites) and converts everything to one line-per-record format. | `data/<profile>/raw/` |
| **Cleaning** | Repairs text, flags suspicious records, removes duplicates, redacts personal data, translates non-English into English. | `data/<profile>/clean/` |
| **EDA gate** | Checks the corpus is good enough: volume, topic balance, no single source dominating. If not, the run stops here. | `logs/<profile>/eda/` |
| **Normalization** | Maps every record onto one canonical 22-field schema, drops near-duplicates, and writes the final dataset with a provenance manifest. | `data/<profile>/final/dataset.jsonl` |

A few ideas hold it together:

- **A source is fetched only if it clears two gates.** Every URL is screened
  before the request (`ingestion/urlscreen.py`: no non-HTTP schemes, no embedded
  credentials, no host resolving to a private or cloud-metadata address, re-checked
  across redirects), *and* its license must clearly allow commercial use. Anything
  else is skipped and logged.
- **Nothing is thrown away quietly.** Dropped records go to `data/<profile>/dropped/`
  with a reason; records needing a human eye go to `flagged/`. Downloads are capped
  and archives are checked for zip bombs before extraction; executables an archive
  ships are reported, never run.
- **Every release is traceable.** The dataset ships with a content-hashed manifest
  recording where each record came from, under what license, and from which pipeline
  version — so a bad batch can be scoped and rolled back.
- **Profiles keep corpora separate.** Each profile (`cybersec`, `ubi`, or one you
  create) has its own catalog, taxonomy, `data/` and `logs/`. Switching profiles
  switches everything; one profile's run never touches another's.

## Quickstart

Needs Python 3.13+ and [uv](https://docs.astral.sh/uv/).

```bash
cp .env.example .env            # API keys — all optional for a basic run
uv sync                         # install the pipeline
uv run cybersec-slm all         # ingest -> clean -> EDA gate -> normalize
uv run cybersec-slm all --resume   # re-run without re-fetching finished sources
```

The finished corpus lands in `data/<profile>/final/dataset.jsonl`. To drive the
pipeline, watch it live, browse the result and ask a Q&A agent about it, all in the
browser:

```bash
uv sync --extra dashboard       # installs Streamlit (opt-in)
uv run cybersec-slm dashboard   # -> http://localhost:8501
```

Sourcing needs a SearXNG instance; `docker-compose.searxng.yml` brings one up
preconfigured. Output folders live at the project root and are git-ignored; point
them elsewhere with `CYBERSEC_SLM_DATA_ROOT`.

For every command and flag, see **[docs/commands.md](docs/commands.md)**.

## Layout

```
src/cybersec_slm/
  core.py         logging, per-profile data paths, JSONL + hashing
  cli.py          the single entry point (source / ingest / clean / eda / schema / all)
  sourcing/       SearXNG discovery + the editable keyword/feed catalog -> Sources.csv
  ingestion/      fetch, scrape, crawl, RSS, URL screen + license gate, binary scan
  cleaning/       sanitize, anomaly, dedup, pii, langfilter, translate, canary tokens
  eda/            metrics + the sufficiency gate
  normalize/      schema, mappers, enrich, dedup, manifest
  dashboard/      Streamlit control center: run stages, monitor, explore, Q&A, security
sources/profiles/<name>/   Sources.csv, keywords.yaml, Blacklist.csv, Excluded.csv
tests/            pytest suite covering every stage
docs/             architecture, commands, schema, sources, and security notes
```

## Security

Security is part of how each stage behaves, not a layer at the end. The two fetch
gates and the provenance manifest above are the spine of it; alongside them, the
cleaning stage redacts PII and can plant canary tokens to detect leaks, and the
dashboard's **Security** page proves each control by exercising it (it builds a
real zip bomb and checks it's refused, points the URL screen at a metadata IP, and
so on) rather than trusting a checklist.

The honest limits of automated PII redaction on a security corpus are in
[pii_limitations.md](docs/pii_limitations.md); the full trust model, per-stage
threats and the prioritized checklist are in
[security-requirements.md](docs/security-requirements.md).

## Docs

| Doc | What's in it |
|---|---|
| [commands.md](docs/commands.md) | Every command, flag and run mode; configuration; development |
| [architecture/architecture.md](docs/architecture/architecture.md) | How the pipeline works, stage by stage, with the data flow |
| [architecture/canonical_schema.md](docs/architecture/canonical_schema.md) | The 22-field record schema (the downstream handoff contract) |
| [pipeline-flow.md](docs/pipeline-flow.md) | Following one record from catalog to finished dataset |
| [security-requirements.md](docs/security-requirements.md) | Trust model, per-stage threats, prioritized checklist |
| [pii_limitations.md](docs/pii_limitations.md) | What the PII pass does and does not catch |
| `docs/sources/` | How sources are researched, evaluated and accepted (incl. legal scope) |

## Status

The five stages are built, wired end to end, and covered by the test suite, with a
Streamlit dashboard driving them from the browser. From here the work is
incremental: adding vetted sources, widening PII coverage, and tuning the
sufficiency thresholds as the corpus grows.
