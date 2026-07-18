# Security Requirements

A stage-by-stage security specification for the cybersec-slm data pipeline. For
every step of the flow it records the **current control** (present, partial, or
missing), the **threats** that step faces, and the **best measure to apply**. A
cross-cutting section follows for concerns that span the whole codebase, and a
prioritized checklist closes the document.

This is a working checklist, not a claim of compliance. Where a control is marked
missing or partial, that is the gap to close, not a description of what exists.

## How to read this document

Requirement levels (RFC 2119 sense):

- **MUST** - required; absence is a security defect.
- **SHOULD** - strongly recommended; deviations need a documented reason.
- **MAY** - defense in depth; apply when the deployment warrants it.

Control status:

- **[present]** - implemented in the code today (file reference given).
- **[partial]** - implemented but incomplete or not enforced by default.
- **[missing]** - documented, intended, or expected, but not in the code.

## Trust model

The pipeline ingests **untrusted content from the public internet** and turns it
into a training corpus. The core trust boundary is between "data discovered or
downloaded from the outside" and "everything the pipeline then does with it."
Every record in `data/raw/` must be treated as attacker-controlled: it can carry
malicious markup, encoded payloads, poisoning text, prompt-injection strings, and
personal data.

```
[public web] --SSRF/poisoning--> Sourcing --> Ingestion --> Cleaning --> EDA --> Normalization --> dataset.jsonl
                                     |            |             |                                        |
                                 SEARXNG_URL  fetch/crawl   PII/hazard                              Dashboard + Agent
                                                                                                   (control plane, NIM egress)
```

Local-first assumption: the pipeline, the dashboard, and its control plane run on
a trusted operator machine. That assumption is itself a security requirement (see
[Dashboard and control plane](#dashboard-and-control-plane)) and breaks the moment
the dashboard is exposed on a network.

## Highest-priority findings

| # | Severity | Finding |
|---|---|---|
| F1 | High | The source **allowlist gate was removed** (commit `3aa6f20`) but `architecture.md`, `README.md`, and `pyproject.toml` still describe `ingestion/allowlist.py` + `sources/allowlist.yaml` as the active anti-poisoning gate. Ingestion currently fetches any catalogued URL with only the license gate in front of it. |
| F2 | High (if exposed) | The dashboard **control plane** can start/stop runs, launch any stage, and **delete all data and logs** with no authentication. Safe only while bound to localhost on a trusted machine. |
| F3 | Medium | Ingestion downloads and unzips remote files with **no size cap and no decompression-bomb guard**; `--max-source-gb` filters on the catalog's declared size, not the bytes actually streamed or extracted. |
| F4 | Medium | Ingestion fetches catalog URLs and **follows redirects with no host/scheme allowlist** (SSRF): internal services and cloud metadata endpoints are reachable if such a URL enters the catalog. |
| F5 | Medium | The Q&A agent sends **untrusted corpus text to a third-party API** (NVIDIA NIM): indirect prompt-injection surface and PII egress for anything the redactor missed. |
| F6 | Low | Sub-Domain names are used **unsanitized** as filesystem path segments and CLI argv (path/argument injection); low risk because the catalog is curated, but not defended in depth. |
| F7 | Low | Documentation drift: `architecture.md` still says "Google Programmable Search" (now SearXNG), and `README.md` links a `docs/risk_register.md` that does not exist. |
| F8 | Info | PII redaction has known false negatives on a security corpus (already documented in [pii_limitations.md](pii_limitations.md)). |

---

## Stage 0: Sourcing (SearXNG discovery)

`sourcing/` - keyword search through a self-hosted SearXNG instance, appending
candidate rows to `sources/Sources.csv`.

**Assets:** the `SEARXNG_URL` endpoint, the editable keyword catalog
(`sources/keywords.yaml`), and the source catalog it writes.

**Threats:** SSRF through a misconfigured or attacker-influenced `SEARXNG_URL`;
poisoning the catalog with attacker-chosen URLs that later get fetched; ingestion
of malicious YAML in the keyword catalog; discovery results themselves being
untrusted.

| Requirement | Level | Status |
|---|---|---|
| Keyword catalog MUST be parsed with a safe loader, never `yaml.load`/pickle | MUST | [present] `catalog.py` uses `yaml.safe_load` and writes with `yaml.safe_dump`. |
| Discovered URLs MUST NOT be fetched automatically; a human reviews the catalog before ingestion | MUST | [present] `discover()` only appends candidate rows; ingestion is a separate stage. |
| `SEARXNG_URL` SHOULD point at a trusted, operator-controlled instance over a private network or loopback | SHOULD | [partial] defaults to `http://localhost:8080`; no validation that the configured host is trusted. |
| The SearXNG request SHOULD enforce a timeout and surface clear errors | SHOULD | [present] `search.py` sets a 30s timeout and raises `SearchError` on failure, 403, or non-JSON. |
| Discovered candidate URLs SHOULD be normalized and screened (scheme in {http,https}, no private/link-local hosts) before being written to the catalog | SHOULD | [missing] `run.discover` dedups and appends but does not screen the host/scheme. |
| SearXNG SHOULD run without the query being logged to a shared instance that leaks the operator's collection intent | MAY | operator-configured in SearXNG `settings.yml`. |

**Best measure:** add a host/scheme screen in `sourcing/` (reject non-`http(s)`,
reject RFC 1918 / loopback / link-local / `*.internal` hosts) at the point a
candidate row is built, so poisoned or SSRF-shaped URLs never reach the catalog a
reviewer approves. Keep discovery strictly propose-only.

---

## Stage 1: Ingestion (fetch, scrape, crawl, API)

`ingestion/` - downloads each catalogued source to `data/raw/` (HuggingFace,
Kaggle, GitHub, raw URLs, PDFs, JSON feeds, crawlable websites, the NVD API).

**Assets:** the network egress path, the local filesystem under `data/raw/`, the
provenance ledger, and API credentials (Kaggle, NVD).

**Threats:** SSRF; supply-chain poisoning (a swapped-out upstream serving
malicious data under a trusted name); path traversal from archive members or
source identifiers; decompression bombs and oversized downloads (DoS); malicious
content reaching later stages; credential leakage.

| Requirement | Level | Status |
|---|---|---|
| A source MUST pass a default-deny commercial-license gate before download | MUST | [present] `license_gate.py`, enforced in `worker.process_source`; deny patterns tested before allow; `CYBERSEC_SLM_ENFORCE_LICENSE_GATE=0` disables it (dev only). |
| An approved-source **allowlist** MUST gate ingestion so a compromised upstream cannot enter under a trusted name | MUST | **[missing]** removed in commit `3aa6f20`; still documented as present. See F1. |
| Each source MUST be fetched in an isolated worker so one bad source cannot crash or contaminate the run | MUST | [present] `ProcessPoolExecutor` per-source isolation in `parallel._run_pool`; failures return a status dict, never crash the pool. |
| A per-source wall-clock timeout MUST bound a hung fetch | MUST | [present] `source_timeout` (default 1800s) swept in `_run_pool`. |
| TLS certificate verification MUST be on for all downloads | MUST | [present] `common.download`/`http_get` use httpx defaults (`verify=True`); no `verify=False` anywhere. |
| Outbound fetch MUST restrict scheme to http/https and MUST NOT reach private/link-local/metadata hosts (SSRF) | MUST | **[missing]** `common.download` follows redirects with no host/scheme screen. See F4. |
| Downloads MUST enforce a maximum byte size, streamed, independent of the catalog's declared size | MUST | **[missing]** no cap in `common.download`; `--max-source-gb` filters catalog metadata only. See F3. |
| Archive extraction MUST reject path-traversal members and MUST bound total uncompressed size / entry count (zip-bomb) | MUST | [partial] CPython `ZipFile.extractall` strips `..`/absolute paths (traversal covered), but there is no uncompressed-size or entry-count cap in `fetch.fetch_url` / `fetch_kaggle`. |
| Source identifiers used as filesystem paths MUST be sanitized | MUST | [partial] `sources.slugify` constrains slugs to `[a-z0-9-]` and caps length; Sub-Domain folder names are used unsanitized (F6). |
| The web crawler MUST obey robots.txt, stay on the same host, and rate-limit | MUST | [present] `crawl_runner.py`: `ROBOTSTXT_OBEY=True`, `allowed_domains`, `allow_prefix`, `CLOSESPIDER_PAGECOUNT`/`TIMEOUT`, `DOWNLOAD_DELAY`, `AUTOTHROTTLE_ENABLED`. |
| The crawler subprocess MUST be launched without a shell and with a bounded timeout | MUST | [present] `scrape_html.crawl` uses a list-form `subprocess` call with a timeout; no `shell=True`. |
| Every produced/skipped file MUST be recorded with provenance (source, url, license, sha256) for later surgical removal | MUST | [present] `common.IngestLog` + `export_ledger` -> `logs/provenance/ledger.csv`. |
| Ingested content MUST be treated as untrusted downstream (no execution, no `eval`) | MUST | [partial] readers parse data as data (`pandas`/`polars`/`json_repair`) and no reader executes fetched content. But the **crawler runs Playwright Chromium** (`scrape_html.py`, `Dockerfile`), which executes remote JavaScript by design: that is the pipeline's one live code-execution surface, and this row used to deny it existed. Binaries inside fetched archives are never executed, and since `binscan` they are at least reported (`logs/binary_scan.jsonl`) rather than deleted unseen. |
| Downloaded artifacts SHOULD be integrity-pinned to an expected hash where the upstream publishes one | SHOULD | [missing] hashes are recorded after download (provenance), not verified against a known-good value (trust-on-first-use). |

**Best measures (in priority order):**
1. **Restore an ingestion allowlist** (F1): re-introduce a version-controlled
   `approved`-status gate keyed on the same `descriptor_key`, checked in
   `worker.process_source` before the license gate. If the allowlist is
   intentionally gone, update `architecture.md`, `README.md`, and `pyproject.toml`
   so the documented control matches reality.
2. **Add an SSRF screen** in `common.download`/`http_get` (F4): resolve the host,
   reject non-http(s), reject private/loopback/link-local/metadata ranges, and
   re-screen after each redirect (or disable auto-redirect and screen manually).
3. **Cap streamed and extracted bytes** (F3): abort a download past a configurable
   size, and bound uncompressed size + entry count during zip extraction.
4. **Sanitize Sub-Domain path segments** (F6) with the same `slugify` discipline
   used for slugs.

---

## Stage 2: Cleaning (sanitize, dedup, PII, hazard scan, language, translate)

`cleaning/` - normalizes text, redacts PII, flags hazards, deduplicates, and
optionally translates non-English records into English.

**Assets:** record text (may contain PII and payloads), the dedup checkpoint,
the translation egress path.

**Threats:** PII leaking into the corpus; malicious active content propagating;
unsafe deserialization of the dedup checkpoint; sending sensitive text to an
online translator; resource exhaustion on pathological inputs.

| Requirement | Level | Status |
|---|---|---|
| PII MUST be redacted with a documented, reviewable pass | MUST | [present] `cleaning/pii.py` (Presidio + spaCy, regex fallback). |
| PII redaction limits MUST be documented and manually reviewed each release | MUST | [present] [pii_limitations.md](pii_limitations.md) + `tools/pii_sample_review.py`. See F8. |
| Security hazards (embedded scripts, JS URIs, base64 blobs, shell-injection patterns, suspicious URLs) MUST be flagged, not silently kept | MUST | [present] `ingestion/hazard_scan.py`, which runs in **Stage 1 ingestion** (`light_eda.assess_source`), not here. Findings are counted by type, with their severity, into the ingest report's `flags.security_hazards`; nothing is dropped (a security corpus legitimately contains payloads) and nothing is quarantined. This row previously claimed hazards were diverted to `data/flagged/` with `_stage=hazard`: no code ever did that, and `data/flagged/` is written only by the cleaning stage's anomaly path. |
| The dedup checkpoint MUST NOT be an executable/deserializable format | MUST | [present] `cleaning/dedup.py` uses JSON checkpoints and explicitly rejects pickle ("deserializing an unvetted pickle is a code-execution risk"). |
| Non-English translation egress MUST be opt-outable, since it sends record text to an online service | SHOULD | [present] `CYBERSEC_SLM_TRANSLATE=off` skips online translation and drops non-English instead; `--drop-non-english` on ingest/clean. |
| The PII redactor SHOULD gain custom recognizers for the recurring security-corpus categories it misses (internal hostnames, private IPs, service accounts, tokens, MAC addresses) | SHOULD | [partial] boundary documented; custom recognizers are the follow-up called for in `pii_limitations.md`. |
| Cleaning SHOULD bound per-record work so a pathological record cannot stall the stage | MAY | [partial] anomaly/length heuristics exist; no explicit regex-DoS budget. |

**Best measure:** treat PII redaction as detection with known gaps, not a
guarantee. Enforce the release-time manual sample review as a gate (not just a
doc), and grow `cleaning/pii.py` recognizers for each category `pii_limitations.md`
lists. Keep hazard findings as flag-for-review; do not let the corpus silently
absorb active content.

---

## Stage 3: EDA sufficiency gate

`eda/` - checks the cleaned corpus for volume, topic balance, source
concentration, and drift, and blocks the run on a failing gate.

**Assets:** the gate thresholds and the append-only run history.

**Threats:** a single poisoned or over-represented source dominating the corpus;
silent threshold weakening; unnoticed distribution drift.

| Requirement | Level | Status |
|---|---|---|
| The gate MUST block the pipeline on a blocking violation | MUST | [present] `run_v2_pipeline` halts on `SufficiencyError`; `--no-enforce` downgrades to report-only (explicit opt-out). |
| A single-source concentration ceiling MUST bound how much one source contributes to a sub-domain | MUST | [present] concentration check in `eda/` against `eda/config.py` thresholds. |
| Gate thresholds MUST be version-controlled and auditable, not silently editable | SHOULD | [partial] thresholds live in `eda/config.py` and are env-overridable; env overrides are not themselves logged into the run history. |
| Run history MUST be append-only for auditability | MUST | [present] versioned run history under `logs/eda/`. |
| Threshold overrides SHOULD be recorded in the run artifact so a weakened gate is visible in the audit trail | SHOULD | [missing] env overrides apply silently. |

**Best measure:** record the effective thresholds (including any env overrides)
into each EDA run artifact, so a run that passed only because a ceiling was
loosened is visible after the fact.

---

## Stage 4: Normalization

`normalize/` - maps cleaned records onto the canonical 22-field schema, dedups,
and writes `data/final/dataset.jsonl` with a content-hashed manifest.

**Assets:** the release dataset, the provenance manifest, reject logs.

**Threats:** schema-field injection (arbitrary domain/label values); leaking raw
rejected content; releasing an untraceable dataset.

| Requirement | Level | Status |
|---|---|---|
| Field values MUST be validated against a schema; domain/label fields MUST come from a fixed allowlist | MUST | [present] Pydantic schema in `normalize/schema.py`; `map_domain` raises on values outside the allowlist; `safe_unsafe` constrained to SAFE/UNSAFE/null. |
| Reject logs MUST default to metadata-only; raw rejected text MUST be gated behind an explicit debug flag | MUST | [present] raw reject text gated behind `CYBERSEC_SLM_DEBUG_REJECTS=1`. |
| Every release MUST ship a content-hashed provenance manifest enabling scoped rollback | MUST | [present] `normalize/manifest.py` writes the manifest alongside the dataset. |
| The manifest SHOULD record the pipeline version / commit for reproducibility | SHOULD | [partial] manifest carries provenance facets; confirm a pipeline-version field is populated. |

**Best measure:** keep the schema allowlist strict and the reject text gated. The
manifest is the control that lets a late-discovered toxic or mis-licensed source
be scoped and removed instead of discarding the whole corpus; ensure it always
carries enough version/provenance to do that.

---

## Dashboard and control plane

`dashboard/` - Streamlit UI plus `control.py`, which launches pipeline stages as
local subprocesses and can delete all pipeline data.

**Assets:** the ability to start/stop processes, run any stage, and delete
`data/` and `logs/`.

**Threats:** unauthenticated control if the dashboard is exposed; command/argument
injection through settings; destructive reset; XSS through rendered content.

| Requirement | Level | Status |
|---|---|---|
| The dashboard and control plane MUST NOT be exposed on an untrusted network without an authenticating reverse proxy | MUST | [partial] binds to localhost by default; `--headless` is for remote use but adds no auth. Enforced only by operator discipline. See F2. |
| Stage subprocesses MUST be launched without a shell | MUST | [present] `control.start`/`build_command` build an argv list; no `shell=True`. |
| Settings values that become argv MUST be validated/whitelisted so they cannot be interpreted as flags or paths | SHOULD | [partial] `build_command` filters to a stage's known flags, but list-valued `--domains` values are passed unsanitized (F6). |
| The stage name MUST be validated against a known set before launch | SHOULD | [partial] callers pass fixed stage strings; `build_command` does not itself reject an unknown stage. |
| Destructive operations (reset) MUST require explicit confirmation and MUST refuse while a run is active | MUST | [present] `control.reset` refuses while running; the UI adds a confirm dialog. |
| Rendered HTML MUST NOT interpolate untrusted content (`unsafe_allow_html`) | MUST | [present] the only `unsafe_allow_html` use is a static CSS string in `ui.inject_css`; no untrusted data is rendered as HTML. |
| The read layer MUST use parameterized SQL | MUST | [present] `common.IngestLog` uses `?` placeholders; the dashboard reads via static queries. |

**Best measures:**
1. Document and enforce the localhost-only assumption; if remote access is needed,
   require an authenticating reverse proxy (F2). Never bind the control plane to a
   public interface.
2. Validate the stage argument against `_STAGE_FLAGS` keys and pass list values in
   `--flag=value` form (or after a `--` separator) so a crafted Sub-Domain cannot
   be read as an option.

---

## Q&A agent (NVIDIA NIM)

`dashboard/agent_client.py` + `agent_tools.py` - an LLM answers questions over the
corpus using read-only tools, backed by a third-party API.

**Assets:** the corpus content (possibly with un-redacted PII), the NIM API key.

**Threats:** indirect prompt injection via poisoned corpus text; data egress of
sensitive content to a third party; runaway tool loops.

| Requirement | Level | Status |
|---|---|---|
| Agent tools MUST be read-only (no run, retry, write, delete, or exec) | MUST | [present] all seven tools in `agent_tools.py` only read; the system prompt states the read-only contract. |
| Tool arguments from the model MUST be treated as untrusted and never trusted as code/paths | MUST | [present] `_call_tool` wraps every call, catches exceptions, caps limits; args feed only data queries. |
| Tool loops MUST be bounded and each request MUST time out | MUST | [present] `MAX_TOOL_ITERATIONS=6`, `DEFAULT_TIMEOUT=60s`. |
| The API key MUST come from the environment and never be logged | MUST | [present] read from `NVIDIA_API_KEY`; not logged. |
| Corpus text sent to the agent MUST be recognized as third-party egress, and untrusted-content prompt injection is possible | SHOULD | [partial] tool outputs are trimmed excerpts; there is no injection sanitization or egress opt-in prompt. |

**Best measure:** keep the read-only tool boundary (it caps the blast radius of
prompt injection to misleading answers, not actions). Treat NIM as an egress
boundary: make the operator aware that corpus excerpts (including anything the PII
pass missed) leave the machine, and consider a local model or a redaction pass on
tool outputs when the corpus is sensitive.

---

## Container runs

`Dockerfile` - the packaged image for running the pipeline outside a dev machine.

| Requirement | Level | Status |
|---|---|---|
| Secrets MUST be injected at runtime, never baked into images | MUST | [present] the image copies no `.env`; keys are passed with `--env-file` at run time. |
| The image MUST NOT run as root | MUST | [present] the Dockerfile creates an unprivileged `app` user (uid 10001) and switches to it. |
| Writable paths MUST be limited to the output volume | MUST | [present] only `/work` and `/app/src` are chowned to the runtime user. |
| Container images SHOULD use immutable tags and scan-on-push | SHOULD | [depends on registry] set at the registry, not in this repo. |

**Best measure:** keep secrets runtime-injected and keep the image running as the
unprivileged user with only the output volume writable.

---

## Cross-cutting requirements

### Secrets management
- Secrets MUST live in `.env` (git-ignored) or the environment, never in code or
  images. **[present]** `.gitignore` excludes `.env`; `core.py` loads it.
- CI MUST scan the full git history for committed secrets. **[present]** gitleaks
  in CI (per README).
- `.env` MUST parse cleanly; a malformed line silently drops the variable.
  **[watch]** a trailing character outside quotes makes python-dotenv skip the
  whole line (observed on the Kaggle token line).
- Secrets MUST NOT be echoed into logs, transcripts, or command lines. **[present]**
  no secret is logged; treat credential values as never-print.

### Dependency and supply chain
- Dependencies MUST be audited for known vulnerabilities. **[present]** `pip-audit`
  in the dev group / CI.
- Dependencies SHOULD be pinned/locked for reproducible installs. **[present]**
  `uv.lock`.
- New third-party models/wheels (spaCy model, fastText) SHOULD be pinned by URL/hash.
  **[partial]** spaCy model pinned by release URL in `[tool.uv.sources]`.

### Deserialization and parsing safety
- YAML MUST use `safe_load`. **[present]** `catalog.py`.
- Checkpoints/caches MUST NOT use pickle. **[present]** JSON in `cleaning/dedup.py`.
- No `eval`/`exec`/`os.system` on any input. **[present]** none in `src/`.

### Filesystem and path safety
- All externally-derived path segments MUST be sanitized. **[partial]** slugs are;
  Sub-Domain folder names are not (F6).
- Data-root and output paths MUST stay under the configured root. **[present]**
  paths derive from `core.data_root()`.

### Network egress, SSRF, and TLS
- TLS verification MUST be on everywhere. **[present]** httpx defaults; no
  `verify=False`.
- Outbound fetches MUST screen host/scheme against SSRF. **[missing]** (F4).
- Every outbound call MUST have a timeout. **[present]** downloads, search, crawl,
  and agent all set timeouts.

### Resource limits and denial of service
- Per-source timeout. **[present]**. Crawl page/time caps + throttle. **[present]**.
- Download byte cap and zip-bomb guard. **[missing]** (F3).
- Bounded parallelism (worker pool). **[present]** `_default_workers`.

### Logging and data minimization
- Reject logs default to metadata-only; raw text behind a debug flag. **[present]**.
- Provenance ledger enables scoped rollback. **[present]**.
- Logs SHOULD avoid record text and secrets by default. **[present]**.

### Access control
- The pipeline assumes a single trusted local operator. There is **no
  authentication or multi-user authorization** anywhere (dashboard, control plane,
  agent). This is acceptable only for local-first use; any shared or networked
  deployment MUST add authentication in front (F2).

---

## Prioritized checklist

Apply top-down; the first four close the highest-severity gaps.

- [x] **F1** Closed, but not by restoring the allowlist. `3aa6f20` removed it deliberately (the catalog is the source list; suitability is decided by code, not a hand-maintained approve list) and that reasoning stands. The risk it named is real because discovery is automated, so the replacement is a rule rather than a list: `ingestion/urlscreen.py` screens every fetch (see F4). Docs corrected.
- [ ] **F2** Enforce localhost-only for the dashboard/control plane; require an auth proxy for any remote access.
- [x] **F3** `common.download` caps the bytes actually arriving and deletes the partial file; `ingestion/archive.safe_extract` checks uncompressed total, entry count and compression ratio from the central directory *before* writing a byte, and refuses traversal entries. Both zip sites use it.
- [x] **F4** `ingestion/urlscreen.py`, wired into both `common.http_get` and `common.download`. Refuses non-HTTP schemes, embedded credentials, and any host *resolving* to a private/loopback/link-local/reserved address. Redirects are followed by hand so every hop is re-screened; `follow_redirects=True` is what made this reachable.
- [ ] **F5** Flag corpus-to-NIM egress to the operator; consider a local model or output redaction for sensitive corpora.
- [ ] **F6** Sanitize Sub-Domain names used as path segments and argv; validate the stage name against `_STAGE_FLAGS`.
- [x] **F7** Corrected here and in `architecture.md`; the dead `risk_register.md` link is gone from `README.md`. Two rows in this document were themselves wrong and are fixed: the hazard scanner never quarantined anything, and the crawler does execute remote JavaScript.
- [ ] **F8** Keep the PII manual sample review as a release gate; add custom recognizers for the categories in `pii_limitations.md`.
- [x] Canary tokens (`cleaning/canary.py`): opt-in, planted as their own labelled records (never spliced into real ones), recorded in `data/final/canaries.json`, and `verify` re-checks they survived the pipeline. This is the only control that says anything about the corpus *after* it leaves.
- [x] Binaries inside fetched archives are reported (`ingestion/binscan.py` -> `logs/binary_scan.jsonl`) instead of being dropped with no log line and then deleted. Magic bytes, not extensions.
- [x] The licence kill switch fails closed: it used to disable the gate for every source on any unrecognised value (`=2`, `=yess`, empty).
- [ ] Record effective EDA thresholds (incl. env overrides) into each run artifact.
- [ ] Integrity-pin downloads to a known hash where the upstream publishes one.
- [ ] Prune `orchestration/flows.SECRET_KEYS` to the current credential set.

## Related documents

- [architecture/architecture.md](architecture/architecture.md) - stage design and the existing security-controls table (note the allowlist drift in F1/F7).
- [pii_limitations.md](pii_limitations.md) - PII redaction gaps and the manual review process.
- [commands.md](commands.md) - flags and environment variables referenced above.
- [operations/deploy.md](operations/deploy.md) - AWS deployment hardening.
