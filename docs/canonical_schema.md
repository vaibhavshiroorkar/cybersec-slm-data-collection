# Canonical Record Schema (`final_data/dataset.jsonl`)

The normalization stage emits one JSON object per line against this 22-field
contract (`src/cybersec_slm/normalize/schema.py::CanonicalRecord`, Pydantic v2,
`extra="forbid"`). The collection pipeline fills every field it can know and
stamps explicit **placeholders** for the fields owned by the downstream labeling
and annotation pipelines, so the record shape is fixed end to end.

| Group | Field | Type | Filled by |
|---|---|---|---|
| Identity | `id` | str (uuid4) | normalize |
| | `content_hash` | str (sha256 hex of `text`) | normalize |
| Content | `text` | str | cleaning → normalize |
| Provenance | `source` | str | extraction |
| | `source_url` | str \| null | extraction |
| | `license` | str (SPDX/best-effort) | extraction |
| | `origin_format` | str (jsonl/csv/pdf/…) | extraction (best-effort) |
| Auto-computed | `lang` | str (ISO 639-1) | normalize |
| | `token_count` | int | normalize |
| | `char_count` | int | normalize |
| Pipeline meta | `pipeline_version` | str (semver) | normalize |
| | `collected_at` | str (ISO 8601 UTC) | normalize |
| Labels | `source_file` | str (routing key) | normalize |
| | `record_type` | str (cve/article/log/…) | normalize (heuristic) |
| | `domain_name` | str (CYBERSEC \| QUANTUM_SEC) | normalize (from routing) |
| | `subdomain_name` | str (12 values) | normalize (from routing) |
| | `domain_label` | int | **placeholder `-1`** → downstream snorkel |
| | `subdomain_label` | int | **placeholder `-1`** → downstream snorkel |
| Annotation | `safe_unsafe` | str \| null | **placeholder `null`** → annotation team |
| | `confidence` | float \| null | **placeholder `null`** → annotation team |
| | `instruction` | str \| null | **placeholder `null`** → annotation team |
| | `reviewed_by` | str \| null | **placeholder `null`** → annotation team |

## Domains

`domain_name` is `CYBERSEC` for the 12 cybersecurity domains and `QUANTUM_SEC`
for the post-quantum track (which maps to the `CRYPTOGRAPHY` subdomain).
`subdomain_name` is one of the 12 canonical values (ordered 0–11 in
`SUBDOMAIN_NAMES`): `APPLICATION, CLOUD, CRYPTOGRAPHY, DATA_PRIVACY, GRC, IAM,
INCIDENT_RESPONSE, MALWARE_ANALYSIS, NETWORK, PENTEST, SECOPS,
THREAT_INTELLIGENCE`. The integer `*_label` codes are emitted as `-1` (ABSTAIN);
the downstream snorkel `LabelModel` assigns the real values against this ordering.

## Identity & re-linking

`id` is a fresh uuid4 per record and is **not** stable across regenerations. Use
`content_hash` (sha256 of the exact `text`) as the stable anchor to re-link a
record if the corpus is rebuilt. Dedup uses a separate *normalized* fingerprint
internally; only `content_hash` (exact) appears on the record.

## Sidecars (same `normalized/` directory)

- `manifest.json` — the release datasheet (counts, license/format/domain
  breakdowns, dataset sha256, git commit, EDA snapshot).
- `rejected.jsonl` — metadata-only reject log (raw text only under
  `CYBERSEC_SLM_DEBUG_REJECTS=1`).
- `duplicates.jsonl`, `dedup_scores.jsonl` — dedup audit trail.
