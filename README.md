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
cp .env.example .env
uv venv
source .venv/bin/activate
uv sync