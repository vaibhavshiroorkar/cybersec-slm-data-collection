# PII Redaction: Known Limitations (Security Corpus)

The cleaning stage redacts PII with Microsoft **Presidio** (regex recognizers +
spaCy NER), falling back to a regex redactor when Presidio is not installed
(`src/cybersec_slm/cleaning/pii.py`). Presidio's dominant failure mode is the
**false negative**: sensitive data it lets through, and a *security* corpus is
unusually prone to it because the sensitive tokens don't look like the
general-purpose PII Presidio was tuned for (threat model Stage 2: "PII Filter
Blind Spots").

## What the automated pass does NOT reliably catch

| Category | Example | Why Presidio misses it |
|---|---|---|
| Internal hostnames | `dc01.corp.internal`, `jumpbox-prod` | not an email/URL/person; no recognizer |
| Private IPs in logs | `10.4.12.9`, `192.168.1.50` | IP recognizer often off or low-confidence in log noise |
| Test/service usernames | `svc_backup`, `admin@lab` | not a PERSON entity; looks like a token |
| API keys / tokens in samples | `AKIA...`, bearer strings | only specific patterns are covered |
| MAC addresses / device ids | `00:1A:2B:3C:4D:5E` | no default recognizer |
| File paths with usernames | `C:\Users\jsmith\...`, `/home/jsmith/` | path, not a PII entity |
| Ticket / case identifiers | `INC0042317` | domain-specific, unknown to Presidio |

## Controls

1. **Documented boundary**: this file. Treat it as the checklist when reviewing.
2. **Scheduled manual review**: sample a random slice of "clean" data and check it
   against the table above *before* it propagates downstream:

   ```bash
   python tools/pii_sample_review.py --n 200      # -> logs/pii_review/sample-<ts>.jsonl
   ```

   Cadence: **every release**, and whenever a new source is added to the allowlist.
   Record findings; if a category recurs, add a custom Presidio recognizer or a
   regex rule to `cleaning/pii.py` and re-run cleaning for the affected sources.
3. **Provenance**: because every record is traceable via the ingest ledger and the
   normalize `content_hash`, a leak found late can be scoped to its source and
   removed surgically (see `logs/provenance/ledger.csv`).

## Out of scope (handled elsewhere)

- Emails, credit cards, phone numbers, person names: covered by the default
  Presidio/regex pass with acceptable recall.
- License compliance: tracked separately in `sources/allowlist.yaml` + the ledger.
