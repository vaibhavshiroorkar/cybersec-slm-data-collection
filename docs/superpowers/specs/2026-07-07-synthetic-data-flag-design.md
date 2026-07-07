# Design: `Is Synthetic?` source flag → excluded from the final dataset

**Date:** 2026-07-07
**Status:** proposed (awaiting review)

## Goal

Add an `Is Synthetic?` column to `sources/Sources.csv`, mark the sources whose
ingested content is synthetic (model-generated, fabricated, or simulated), and
keep those records out of the final training corpus (`data/final/dataset.jsonl`)
— without deleting them (they stay auditable, same as `rejected` / `duplicates`).

## Scope decisions (agreed)

- **What counts as synthetic (broad):** explicitly synthetic/simulated/generated
  datasets, fully machine-generated fabricated-data sets (e.g. generated PII), and
  LLM/machine-generated instruction & Q&A sets.
- **Where the exclusion happens:** at the **normalize** stage. Synthetic sources
  are still fetched, cleaned, and counted by the EDA gate; they are only excluded
  from `dataset.jsonl`. This matches "ingest it, but don't include it in final."
- **Existing data:** the user will re-run the full pipeline afterward, so the
  local `data/` tree is treated as disposable scratch. The filter still reads the
  CSV live at normalize time, so a re-run isn't strictly required to take effect.
- **Refinement — flag the *ingested artifact*, not the referenced data.** A row is
  flagged only when what the pipeline actually ingests is synthetic. Sources whose
  ingested artifact is a real academic paper or repo README that merely *describes*
  a synthetic dataset are **not** flagged (see the marking list).

## Key design fact: the join key

The normalize stage keys work by source folder slug, but slugs are **not** unique:
`darkknight25` is the slug for ~7 different datasets, two of them even in the same
sub-domain (`Cryptography`). So folder/slug matching would wrongly group distinct
datasets.

Every dataset record instead carries a `url` field (injected at ingestion by
`enrich_df` / `to_jsonl`, or already present in the source data). For HF/Kaggle
sources that `url` embeds the canonical `datasets/<org>/<name>` ref — even when it
is a per-file `/resolve/main/...` URL. The CSV `Dataset Link` carries the same ref.

Verified locally:
- `ai4privacy` record `url` = `https://huggingface.co/datasets/ai4privacy/pii-masking-200k/resolve/main/english_pii_43k.jsonl`
- `darkknight25` record `url` = `https://huggingface.co/datasets/darkknight25/phishing_benign_email_dataset/resolve/main/...`

Extracting `datasets/<org>/<name>` from both sides (the same
`/datasets/([^/]+/[^/?#]+)` pattern already used in `sources.py` and
`allowlist.py`) yields a reliable per-record identity that survives slug
collisions. Non-HF/Kaggle sources fall back to a normalized full-URL comparison
(lowercased, trailing slash stripped, matched by prefix).

## Components

### 1. CSV column
- Add `Is Synthetic?` to `sources/Sources.csv`, positioned **after `Verified?`**
  so it groups with the other curation flags (`Uploaded?`, `Cleaned?`,
  `Verified?`, `Is Synthetic?`, then `Date Added`, `Note`).
- Value convention identical to the sibling flags: **`Yes`** = synthetic,
  **blank** = not.
- Schema is defined once in `CATALOG_COLUMNS` in
  `src/cybersec_slm/ingestion/sources.py`; update it there so the sourcing crawler
  (appends rows) and the cleaning driver (writes back `Cleaned*`) stay aligned.
- Header normalization (`_norm_headers`) turns `Is Synthetic?` into the key
  `is_synthetic?` (the trailing `?` is preserved, exactly like `uploaded?`). Any
  reader must look up `is_synthetic?` (with `is_synthetic` as a tolerant alias).
- Verify `src/cybersec_slm/sourcing/row.py` and `sourcing/sheet.py` build/write
  rows **by column name**, not by position; adjust if a positional assumption
  exists so inserting a mid-list column doesn't shift data.

### 2. Synthetic identity set — `sources.py`
- New helper `synthetic_identities(spec=DEFAULT_CATALOG) -> frozenset[str]`.
- Reads `Sources.csv`, selects rows where `is_synthetic?` is truthy (`_bool`),
  and for each computes a normalized identity from `Dataset Link`:
  - HF/Kaggle → `hf:<org>/<name>` / `kaggle:<org>/<name>` (lowercased), via the
    existing `/datasets/([^/]+/[^/?#]+)` extraction.
  - otherwise → `url:<normalized full url>`.
- Reuses `_norm_headers`, `_val`, `_bool`; no new CSV-parsing code path.

### 3. The filter — `normalize/synthetic.py` (new)
- `SyntheticFilter` loads `synthetic_identities()` once.
- `is_synthetic(rec: dict) -> bool`: normalizes `rec.get("url")` /
  `rec.get("source_url")` with the same extraction and checks membership; applies
  the full-URL prefix fallback when there's no `datasets/` ref.
- Pure and independently testable; no dependency on normalize internals.

### 4. Wire into the normalizer — `normalize/pipeline.py`
- Add sink `EXCLUDED_SYNTHETIC = data/final/excluded_synthetic.jsonl` and a
  `_Sink` for it (same lazy-append pattern as `rejected`/`duplicates`).
- Add a `synthetic_excluded` counter key.
- In `Normalizer.process()`, **before** the mapper step: if
  `self.synthetic.is_synthetic(rec)`, write a metadata record
  (`{id?, source, domain, url, reason: "synthetic-source"}`) to the excluded sink,
  bump `synthetic_excluded`, and `return`. Nothing reaches `dataset.jsonl`.
- `_report()` adds `synthetic_excluded` to counts and the new path to `outputs`;
  the summary log line mentions it.

### 5. Tests
- `SyntheticFilter` / matcher unit tests: resolve-URL vs bare `Dataset Link`, HF
  vs Kaggle, non-HF full-URL fallback, and a clear non-match (real source not
  excluded). Include a slug-collision case (two `darkknight25` refs, only one
  flagged → only that one matches).
- `synthetic_identities()` reads a flag correctly from a small fixture CSV.
- `Normalizer` integration test: a synthetic-flagged record lands in
  `excluded_synthetic.jsonl` and is absent from `dataset.jsonl`; a normal record
  is unaffected.

## Data flow

```
sources/Sources.csv  (Is Synthetic? = Yes)   <-- human-curated source of truth
      |  synthetic_identities()
      v
normalize.SyntheticFilter (ref set)
      |
data/clean/** record --process()--> is_synthetic(rec)?
      |                                   |yes--> data/final/excluded_synthetic.jsonl  (counted, not in corpus)
      |no
      v
   mapper -> validate -> dedup -> data/final/dataset.jsonl
```

## Marking list (proposed `Is Synthetic? = Yes`)

Definition applied: flag when the **ingested artifact itself** is
model-generated, fabricated, or simulated. Templated reformatting of real records
(e.g. real CVE fields arranged as instructions) is **not** synthetic.

**High confidence**
| Row | Name | Dataset Link | Why |
|--|--|--|--|
| 2 | CyberNative | .../CyberNative/Code_Vulnerability_Security_DPO | LLM-generated secure/insecure code DPO pairs |
| 12 | sims2k | .../sims2k/GDPR_QA_instruct_dataset | LLM-generated Q&A instruct set |
| 24 | darkknight25 | .../darkknight25/Advanced_SIEM_Dataset | self-described "Synthetic SIEM" logs |
| 68 | ai4privacy-200k | .../ai4privacy/pii-masking-200k | generated/fabricated PII (verified locally) |
| 69 | ai4privacy-300k | .../ai4privacy/pii-masking-300k | generated/fabricated PII |
| 162 | racineai | .../racineai/VDR_Quantum_Circuit_Synthetic | self-described synthetic quantum-circuit data |

**LLM-generated Q&A / instruction (broad scope)**
| Row | Name | Dataset Link |
|--|--|--|
| 4 | AYI-NEDJIMI | .../AYI-NEDJIMI/cloud-security-en |
| 10 | ethanolivertroy | .../ethanolivertroy/nist-cybersecurity-training |
| 25 | pAILabs | .../pAILabs/infosec-security-qa |
| 26 | AlicanKiraz0 | .../AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.1 |
| 27 | reloading0101 | .../reloading0101/threat-intelligence-dataset |
| 62 | AlicanKiraz0 | .../AlicanKiraz0/Cybersecurity-Dataset-v1 |

**Borderline — flagged per broad-scope decision**
| Row | Name | Dataset Link | Note |
|--|--|--|--|
| 5 | darkknight25 | .../darkknight25/Cloud_Vulnerabilities_Dataset | generated-looking |
| 6 | darkknight25 | .../darkknight25/Cryptanalysis_Toolkit_Dataset | generated-looking |
| 72 | darkknight25 | .../darkknight25/Incident_Response_Playbook_Dataset | generated playbooks |
| 83 | darkknight25 | .../darkknight25/phishing_benign_email_dataset | fabricated (verified locally) |
| 96 | darkknight25 | .../darkknight25/Smart_Contract_Vulnerability_Dataset | generated-looking |
| 161 | merileijona | .../merileijona/quantum-circuits-21k | generated NL→QASM pairs |
| 163 | samuellimabraz | .../samuellimabraz/quantum-assistant | generated multimodal set |
| 18 | ziya07 | kaggle .../ziya07/network-security-dataset | simulated 6G |
| 71 | rasikaekanayakadevlk | kaggle .../user-activity-dataset | simulated behavioral auth |
| 80 | dnkumars | kaggle .../cybersecurity-intrusion-detection-dataset | simulated intrusion |

**Recommend NOT flag (ingested artifact is real, not the synthetic data)**
| Row | Name | Reason |
|--|--|--|
| 165 | QuantumLLMInstruct | arXiv **PDF paper**; the ingested artifact is the paper text, not the 500k synthetic pairs it describes |
| 175 | QNLab-USTC | GitHub **repo README** (MD, 1 line); ingested text is real, not the simulated key-data files |

**Deliberately NOT flagged (real data)**
- 21 `ALPHAzero1233 All-CVE` — real CVE text formatted as instructions (templated ≠ synthetic)
- 28 `Shomi28 cyber-threat-intelligence` — real CVE + ATT&CK CTI
- 15 / 66 / 127 `cyberprince` sets — real compiled reference/payload data

> Open question for review: flag rows **165** and **175** anyway (they'd exclude a
> single real paper / README line each), or leave them unflagged as recommended?

## Non-goals / YAGNI

- No mirroring of the flag into `allowlist.yaml` — the CSV is the single source of
  truth for this flag.
- No per-record ingestion-time stamping of a `synthetic` field — the normalize
  filter reading the CSV live is simpler and needs no re-ingest to change a mark.
- No new CLI flag — exclusion is always on (a synthetic mark means "not in final").

## Risks

- **Mis-marking a real source** → it gets excluded. Recoverable: unflag in the CSV
  and re-run normalize; nothing is deleted (records land in
  `excluded_synthetic.jsonl`).
- **A synthetic source whose records carry no `url`** → not matched. All current
  synthetic candidates are HF/Kaggle datasets whose records carry `url`, so this
  is not a live gap; the full-URL fallback covers the non-HF case.
```
