# Cleaning

Second stage of the pipeline. Reads the raw JSONL produced by
[extraction](../extraction) under [`../raw_data`](../raw_data) and turns it into
a clean, de-duplicated, PII-free, English-only corpus ready for EDA.

```
raw_data/
   │
   ▼
Structural Sanitization     fix encoding, missing fields, date formats
   │
   ▼
Anomaly Check ─ behavioral ──▶ ../flagged/  (→ Data Annotation Team)
   │  structural: fix or drop ──▶ ../dropped/
   ▼
Deduplication               exact (sha256) + near-dup (MinHash/LSH)
   │
   ▼
PII Removal                 Presidio (→ regex fallback)
   │
   ▼
Language filtering          fastText lid.176 (→ langdetect/heuristic)
   │  non-English → translate to English (deep-translator → argos); keep
   │  untranslatable non-English ──▶ ../dropped/
   ▼
../cleaned/  → handoff for EDA
```

## Data flow
- **Input:** `../raw_data/<Sub-Domain>/<source>/*.jsonl`
  (records shaped `{source, url, license, page?, text}`; tolerant of missing/extra fields).
- **Outputs** (project root, mirroring the raw_data layout):
  - `../cleaned/…jsonl` — passed every stage. Original schema preserved
    (translated records gain `_orig_lang` and an English `text`).
  - `../flagged/…jsonl` — behavioral anomalies for the annotation team (`_reason` added).
  - `../dropped/…jsonl` — structural / duplicate / untranslatable-non-English drops (`_reason` added).
  - `../logs/clean_report.csv` — per-file counts + a TOTAL row.
  - `../logs/cleaning.log` — run log.

## Modules
| File | Purpose |
|---|---|
| `common.py` | project-rooted paths, logger (loguru→stdlib), streaming JSONL I/O, `try_import`, tunables |
| `sanitize.py` | encoding fix (ftfy→heuristic), NFC, control/whitespace cleanup, fill fields, ISO dates |
| `anomaly.py` | classify `clean` / `structural` (drop) / `behavioral` (flag) |
| `dedup.py` | exact sha256 + near-dup MinHash+LSH (datasketch→pure-python) |
| `pii.py` | Presidio analyze+anonymize → regex fallback (email/phone/IP/CC/SSN) |
| `langfilter.py` | fastText `lid.176` → langdetect → stopword/script heuristic |
| `translate.py` | non-English → English: deep-translator (Google) → argostranslate → no-op |
| `pipeline.py` | runs the stages in order over raw_data + writes the report |
| `run.py` | CLI: `all` / `sanitize` / `dedup` / `pii` / `lang` / `report` |
Tests live in the top-level `tests/cleaning/` (pytest, no heavy deps needed).

## Usage
```bash
cybersec-slm clean all              # full pipeline -> cleaned/ flagged/ dropped/ + report
cybersec-slm clean all --limit 100  # smoke run: cap 100 records per file
cybersec-slm clean sanitize         # diagnostic single-stage run -> _stages/sanitize/
cybersec-slm clean dedup            # -> _stages/dedup/
cybersec-slm clean pii              # -> _stages/pii/
cybersec-slm clean lang             # -> _stages/lang/
cybersec-slm clean report           # recount existing cleaned/flagged/dropped trees
```

## Dependencies are optional
Every named tool has a standard-library fallback, so the stage runs with nothing
extra installed — each module logs which backend it chose. Install the extras to
upgrade quality:

```bash
uv sync --extra cleaning     # ftfy, dateutil, datasketch, presidio, fasttext, langdetect, deep-translator
python -m spacy download en_core_web_lg   # required by presidio
# fasttext also needs a lid.176.ftz / lid.176.bin model in this folder
# (or set FASTTEXT_LID_MODEL to its path)
```

Run the tests with `uv sync --extra dev` then `pytest` from this folder.

## Tunables (`common.py`)
`MIN_TEXT_CHARS` (50), `MAX_TEXT_CHARS` (100k), `GARBAGE_MAX` (0.30),
`REPEAT_MAX` (0.50), `NEAR_DUP_THRESHOLD` (0.85), `SHINGLE_SIZE` (5),
`MINHASH_PERM` (128), `LANGS` (`{"en"}`).

## Notes
- Deduplication is **global across the corpus** and holds an in-memory MinHash/LSH
  index — fine at the current corpus size. For a much larger corpus, swap to a
  disk-backed index (e.g. datasketch's Redis/Cassandra backends) or shard by sub-domain.
- Records keep their original schema in `cleaned/`; provenance/`_reason` fields
  are attached only in `flagged/` and `dropped/`.
