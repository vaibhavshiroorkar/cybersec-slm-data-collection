# Cybersecurity SLM Data Pipeline

This project gathers cybersecurity text from across the web and turns it into a
clean, training-ready corpus for a small language model. It's split into two
stages that you can run on their own or back to back:

- **Extraction** — pull data from each source (datasets, PDFs, feeds, a few
  crawlable sites) and normalize everything to JSONL.
- **Cleaning** — take that raw JSONL and sanitize it, check it for anomalies,
  drop duplicates, strip out PII, and normalize the language to English
  (translating non-English text rather than dropping it).

It's packaged as a proper installable package (`cybersec_slm`) with a single
CLI, so you don't have to remember which script lives where.

EDA, schema normalization, and CI are deliberately left for later — the goal
here was to get extraction and cleaning solid first.

## How it's laid out

```
src/cybersec_slm/
  core.py        the bits both stages share: logging, data paths, JSONL + hashing
  cli.py         one entry point — extract / clean / all
  extraction/    fetch.py, scrape.py, scrape_html.py, manifest.py, run.py
  cleaning/      sanitize, anomaly, dedup, pii, langfilter, pipeline.py, run.py
tests/           a test suite for both stages (pytest)
sources/ docs/   the research notes behind which sources made the cut
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
cybersec-slm extract all      # collect everything into raw_data/
cybersec-slm clean all        # raw_data/ -> cleaned/, flagged/, dropped/, + a report
cybersec-slm all              # do both, in order
```

`extract` also takes `scrape`, `fetch`, `html`, or `table`; `clean` takes the
individual stage names plus `report`. If you'd rather not install the console
script, `python -m cybersec_slm <stage> ...` does the same thing.

## Working on it

```bash
pytest                 # run the tests
ruff check src tests   # lint
```

## Where things stand

- **Week 1** — researched the sources, checked licensing, settled on a shortlist.
- **Week 2** — built the extraction and cleaning stages and packaged the whole
  thing up (src layout, a real CLI, tests for both stages).
- **Next** — EDA, normalizing the record schema, and wiring up CI.
