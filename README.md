# Cybersecurity SLM Data Pipeline

A pipeline to collect, clean, and consolidate cybersecurity text data for SLM training.

## Structure
- /sources - source research and notes
- /extraction - scripts to pull data from each source
- /scripts - utility scripts for cleaning and conversion
- /raw_data - collected raw data in JSONL format
- /logs - collection logs
- /docs - documentation, schema, and templates

## Setup
```bash
cp .env.example .env
uv venv
source .venv/bin/activate
uv sync
```

## Progress
- Day 1: project setup, folder structure, schema, and documentation templates
- Day 2: 18 cybersecurity data sources identified and documented
- Day 3: licensing verified, sources scored and ranked, shortlist of 12 confirmed (in progress)
- Day 4: extraction methods assigned (in progress)