# Taxonomy restructure, source expansion, and frontend rebuild

Date: 2026-07-09

## Goal

Restructure the sub-domain taxonomy, grow the source catalog to 300 rows, rebuild
the Streamlit dashboard, refresh the docs, reset the data/logs state, and run the
full pipeline end to end.

Execution is checkpointed: stop for user approval at four gates (A: after taxonomy,
B: after crawl candidates, C: before deleting data/, D: before the pipeline run).

## Phase 1: Taxonomy restructure

Final taxonomy is 12 canonical domains (Quantum removed as a top-level domain):

1. Application Security
2. Network Security
3. Cloud Security
4. Identity Access and Management
5. Incident Response and Forensics
6. Data Security and Privacy
7. Penetration Testing
8. Vulnerability Management
9. Governance, Risk and Compliance
10. Cryptography
11. Security Operations
12. Threat Intelligence

Changes:
- Malware Analysis (10 rows) folds into Threat Intelligence.
- Quantum (86 rows, all post-quantum cryptography) folds into Cryptography.
- "Penetration Testing and Vulnerability Management" (11 rows) splits into
  Penetration Testing (offensive: exploits, CAPEC, GTFOBins, pentest guides) and
  Vulnerability Management (CVE/CWE/NVD/patch management).
- Fix the "Forsenics" typo to "Forensics" in the CSV.

Files: `sources/Sources.csv`, `src/cybersec_slm/sourcing/keywords.py`,
`src/cybersec_slm/normalize/schema.py`, `src/cybersec_slm/ingestion/sources.py`,
and the affected tests. Schema keeps parallel `CANONICAL_DOMAINS` /
`SUBDOMAIN_NAMES` tuples in sync; drop the `QUANTUM_SEC` domain_name and the
`MALWARE_ANALYSIS` subdomain, add `VULN_MANAGEMENT`. Run the full test suite before
Gate A.

## Phase 2: Source expansion to 300

Use `cybersec-slm source` (Google Programmable Search, keys in `.env`) against the
new 12-domain keyword catalog. Need about 108 net-new rows. Dry-run first, dedup
candidates against the existing catalog, present them at Gate B, then append.

## Phase 3: Frontend rebuild

Keep Streamlit, the read-only `data.py` layer, and the Pipeline/Dataset/Agent
pages. Rebuild the presentation: a theme in `.streamlit/config.toml`, a landing
dashboard with KPI tiles, real charts, and polished filterable tables. No change to
what the pipeline writes; the dashboard stays read-only.

## Phase 4: Docs and memory

Update `README.md`, the dashboard README, `docs/commands.md`, and taxonomy
references in `docs/new3.tex`. Record the standing rule: never use em dashes.

## Phase 5: Reset and push

Delete `data/`, reset `logs/` and run state, reconcile and commit the existing
branch WIP plus these changes, and push as the user (no Claude attribution).

## Phase 6: Pipeline run

Run `cybersec-slm all` (ingest, clean, EDA, normalize) on the 300-source catalog
after Gate D.

## Notes

Merging 86 Quantum rows into Cryptography makes it the largest domain by source
count. EDA auto-rebalancing keeps the final record counts balanced downstream.
