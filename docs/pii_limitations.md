# PII Redaction: Known Limitations (Security Corpus)

The cleaning stage redacts PII with Microsoft **Presidio** (regex recognizers +
spaCy NER), falling back to a regex redactor when Presidio is not installed
(`src/cybersec_slm/cleaning/pii.py`). Presidio's dominant failure mode is the
**false negative**: sensitive data it lets through, and a *security* corpus is
unusually prone to it because the sensitive tokens don't look like the
general-purpose PII Presidio was tuned for (threat model Stage 2: "PII Filter
Blind Spots").

## Now covered (added to the regex pass)

Each of these is high-signal by construction — a fixed vendor prefix, a checksum,
or a required context cue — so it redacts without eating ordinary corpus text:

| Category | Example | How it is asserted |
|---|---|---|
| API keys / tokens | `AKIA…`, `ghp_…`, `xox…`, `AIza…`, `sk_live_…`, JWTs | issuer-specific prefix |
| Private keys | `-----BEGIN RSA PRIVATE KEY-----…` | whole PEM block removed |
| MAC addresses | `00:1A:2B:3C:4D:5E` | six hex pairs, anchored so a sha256 cannot match |
| Usernames in paths | `C:\Users\jsmith\…`, `/home/jsmith/` | only the name component is replaced |
| India PAN | `ABCDE1234F` | 5 letters + 4 digits + 1 letter |
| India Aadhaar | `2341 2345 6783` | Verhoeff checksum **and** a nearby `aadhaar`/`uidai` cue |

## Still NOT caught — and why

| Category | Example | Why it is left alone |
|---|---|---|
| Private IPs in logs | `10.4.12.9`, `192.168.1.50` | **Deliberate.** RFC1918/loopback/TEST-NET are not PII and carry real teaching value in security text (see `pii.py::_ip_ok`). |
| Public author names | NIST/RFC bylines | **Deliberate.** Overwhelmingly citation, not PII — so PERSON redaction is opt-in (`--pii-engine presidio`). |
| Internal hostnames | `dc01.corp.internal`, `jumpbox-prod` | No assertable shape; a pattern loose enough to catch it also eats ordinary dotted identifiers and version strings. |
| Test/service usernames | `svc_backup`, `admin@lab` | Not a PERSON entity; indistinguishable from an ordinary token. |
| Ticket / case identifiers | `INC0042317` | Site-specific, and shaped like the many other alphanumeric ids a security corpus is full of. |

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
   removed surgically (see `logs/<profile>/provenance/ledger.csv`).

## Out of scope (handled elsewhere)

- Emails, credit cards, phone numbers, person names: covered by the default
  Presidio/regex pass with acceptable recall.
- License compliance: enforced by the ingestion license gate
  (`src/cybersec_slm/ingestion/license_gate.py`, default-deny) against each row's
  `License` in the active profile's `sources/profiles/<profile>/Sources.csv`.
