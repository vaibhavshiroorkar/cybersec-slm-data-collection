# Cleaning

Second stage of the pipeline. Reads the raw JSONL produced by
[ingestion](../ingestion) under `data/raw/` and turns it into a clean,
de-duplicated, PII-free, English-only corpus ready for EDA.

```
data/raw/
   │
   ▼
Structural Sanitization     fix encoding, missing fields, date formats
   │
   ▼
Anomaly Check ─ behavioral ──▶ data/flagged/  (→ Data Annotation Team)
   │  structural: fix or drop ──▶ data/dropped/
   ▼
Deduplication               exact (sha256) + near-dup (MinHash/LSH)
   │
   ▼
PII Removal                 Presidio (→ regex fallback)
   │
   ▼
Language filtering          fastText lid.176 (→ langdetect/heuristic)
   │  non-English → translate to English (deep-translator → argos); keep
   │  untranslatable non-English ──▶ data/dropped/
   ▼
data/clean/  → handoff for EDA
```

## Data flow
- **Input:** `data/raw/<Sub-Domain>/<source>/*.jsonl`
  (records shaped `{source, url, license, page?, text}`; tolerant of missing/extra fields).
- **Outputs** (under `data/`, mirroring the `data/raw` layout):
  - `data/clean/…jsonl`: passed every stage. Original schema preserved
    (translated records gain `_orig_lang` and an English `text`).
  - `data/flagged/…jsonl`: behavioral anomalies for the annotation team (`_reason` added).
  - `data/dropped/…jsonl`: structural / duplicate / untranslatable-non-English drops (`_reason` added).
  - `logs/clean_report.csv`: per-file counts + a TOTAL row.
  - `logs/cleaning.log`: run log.

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
| `pipeline.py` | per-source cleaning (`clean_one_source`) + deterministic, resumable cross-source `final_global_dedup`; writes the report |
| `run.py` | CLI diagnostics: `sanitize` / `dedup` / `pii` / `lang` / `report` / `balance` |
Tests live in the top-level `tests/cleaning/` (pytest, no heavy deps needed).

## Usage
Production cleaning runs fused with ingestion, one worker per source, via
`cybersec-slm run` (or `all`) — there is no batch `clean all`. The `clean` command
is for diagnostics and ops: inspecting one transform in isolation, or reporting.

```bash
cybersec-slm run                    # ingest + clean every source -> data/clean/ (production path)
cybersec-slm clean sanitize         # diagnostic single-stage run -> data/_stages/sanitize/
cybersec-slm clean dedup            # -> data/_stages/dedup/
cybersec-slm clean pii              # -> data/_stages/pii/
cybersec-slm clean lang             # -> data/_stages/lang/
cybersec-slm clean report           # recount existing data/clean, data/flagged, data/dropped trees
cybersec-slm clean balance          # per-domain record counts (--cap N to downsample)
```

## Dependencies
Every named tool (ftfy, dateutil, datasketch, presidio, fastText, langdetect,
deep-translator) plus the spaCy model presidio loads is a **base dependency**.
`uv sync` from the repo root installs all of it, and `pytest` is there too (dev
group). Each module still has a standard-library fallback and logs which backend
it chose, so the stage never hard-fails if something is missing.

```bash
uv sync                      # the cleaning stack + spaCy model + dev tools
# fastText also needs a lid.176.ftz / lid.176.bin model in this folder
# (one ships in the repo; or set FASTTEXT_LID_MODEL to its path)
```

## Tunables (`common.py`)
`MIN_TEXT_CHARS` (50), `MAX_TEXT_CHARS` (100k), `GARBAGE_MAX` (0.30),
`REPEAT_MAX` (0.50), `NEAR_DUP_THRESHOLD` (0.85), `SHINGLE_SIZE` (5),
`MINHASH_PERM` (128), `LANGS` (`{"en"}`).

## Notes
- Deduplication is **global across the corpus** and holds an in-memory MinHash/LSH
  index, fine at the current corpus size. For a much larger corpus, swap to a
  disk-backed index (e.g. datasketch's Redis/Cassandra backends) or shard by sub-domain.
- Records keep their original schema in `data/clean/`; provenance/`_reason` fields
  are attached only in `data/flagged/` and `data/dropped/`.
