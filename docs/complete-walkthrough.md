# Complete Walkthrough

This is the long-form guide to the whole project. It explains, in plain language,
what every part of the code does, why it is there, and how the pieces fit
together. If the README tells you how to run the pipeline and the architecture
doc gives the shape of it, this document is the one you read when you want to be
able to describe every single thing that happens, stage by stage and file by
file.

Nothing here assumes you already know the code. Read it top to bottom the first
time, then use the section headings as a reference later.

---

## 1. What the project is

The goal is to build the training data for a small cybersecurity language model.
A small language model (SLM) is a transformer with a few billion parameters or
fewer that can run on ordinary hardware without a cloud API. Its quality depends
almost entirely on the quality of the text it is trained on, so the hard part is
not the model, it is the data.

Good cybersecurity text exists in plenty: CVE feeds, NIST publications, MITRE
catalogs, research datasets, security blogs. The trouble is that it is scattered
across dozens of formats and sites, mixed with noise, duplicates, and personal
data, and none of it arrives in the shape a model wants. This project does that
unglamorous middle work. It gathers the good material from a vetted list of
sources and turns it into one clean, consistent, training-ready corpus that you
can trust and trace back to where each record came from.

The whole thing ships as an installable Python package called `cybersec_slm`,
driven by a single command, `cybersec-slm`. You can run the entire pipeline end
to end or one stage at a time.

The central design idea is worth stating up front, because it explains most of
the choices below: **every stage treats its input as possibly messy or
untrustworthy.** Problems are flagged, dropped, or quarantined with a reason,
never allowed to slip downstream unnoticed. Security is not a layer bolted on at
the end. It is how each stage behaves.

---

## 2. The big picture

The work happens in five stages. Each one hands its output to the next.

```
Sourcing  ->  Ingestion   ->  Cleaning   ->  EDA gate  ->  Normalization  ->  dataset.jsonl
(optional)     data/raw/      data/clean/   (pass?)        data/final/         + manifest.json
```

| Stage | In plain terms | Output |
|---|---|---|
| Sourcing (optional) | Searches the web for new candidate sources and adds them to a catalog for a human to review. Nothing here is trusted automatically. | `sources/Sources.csv` |
| Ingestion | Downloads each approved source (datasets, PDFs, feeds, crawlable sites, the NVD CVE API) and converts everything into one simple line-per-record format. | `data/raw/` |
| Cleaning | Builds a text field, flags suspicious records, removes duplicates, redacts personal data, and translates non-English text into English. | `data/clean/`, plus `flagged/` and `dropped/` |
| EDA gate | Checks whether the corpus is actually good enough: enough volume, balanced across topics, not dominated by one source. A hard failure stops the run. | `logs/eda/` |
| Normalization | Maps every record onto one canonical 22-field schema, removes exact duplicates, keeps synthetic sources out, and writes the final dataset with a provenance manifest. | `data/final/dataset.jsonl` + `manifest.json` |

One important detail about how a run actually executes: **ingestion and cleaning
are fused and run in parallel.** They are not two separate passes. One worker
process handles one source at a time, from fetch to clean, and there are several
workers going at once. After the pool of workers drains, a single cross-source
deduplication pass runs, then the EDA gate, then normalization. This is the
"overlapped ingest and clean" design, and it is the reason peak disk usage stays
small even for multi-gigabyte sources.

---

## 3. Repository layout

Here is what lives where. Generated data (`data/`, `logs/`) is git-ignored, so
the repository itself stays code-only.

```
src/cybersec_slm/
  core.py            shared plumbing: optional imports, .env loading, data paths, logger, JSONL + hashing
  cli.py             the single entry point (one subcommand per stage)
  __main__.py        lets you run the package with `python -m cybersec_slm`
  sourcing/          web search source discovery, appends candidate rows to Sources.csv
  ingestion/         fetch, scrape, crawl, the license gate, the light EDA gate, the parallel worker pool
  cleaning/          text mapping, sanitize, anomaly, dedup, PII, language filter, translate
  eda/               corpus metrics and the sufficiency gate
  normalize/         schema, mappers, enrich, dedup, synthetic filter, manifest
  orchestration/     the Prefect build-corpus flow
  dashboard/         read-only Streamlit monitor, dataset explorer, and Q&A agent
sources/             Sources.csv (the curated catalog) and the research behind it
tests/               a pytest suite covering every stage
docs/                architecture, commands, schema, deployment, and security notes
infra/               a Terraform skeleton (ECR / ECS / S3 / IAM / Secrets Manager)
tools/               small helper scripts (allowlist build, PII sampling, pipeline runner)
```

A few top-level files matter too:

- `pyproject.toml` declares the package, its dependencies, and the optional
  extras (orchestration, dashboard, agent).
- `dvc.yaml` describes the reproducible corpus build for DVC.
- `prefect.yaml` describes the Prefect deployment.
- `Dockerfile` builds the container image used for hosted runs.
- `.github/workflows/` holds the CI (secret scanning, dependency audit, lint,
  tests) and the deploy workflow.

A note on documentation drift: the README, `docs/architecture/architecture.md`,
and `dvc.yaml` still mention a source allowlist file (`sources/allowlist.yaml`)
and an `ingestion/allowlist.py` module. Those are no longer part of the code. The
governance gate that actually runs at ingestion today is the commercial-license
gate (Section 7.4) plus the light EDA gate (Section 7.5), and synthetic sources
are held out at normalization (Section 10.4). This walkthrough describes what the
code does now.

---

## 4. Core plumbing: `core.py`

Everything else builds on `core.py`. It holds the handful of things every stage
needs, so there is one place per purpose instead of five copies.

- **Optional-dependency loader.** `try_import(name)` imports a module and returns
  `None` if it is not installed, instead of raising. This is the mechanism behind
  the pipeline's "degrade gracefully" behavior: a cleaning step that cannot find
  its preferred library falls back to a standard-library heuristic and logs which
  backend it used.
- **`.env` loading.** On import, if `python-dotenv` is present, `core.py` loads a
  project `.env` file so API keys land in the environment before any stage reads
  them. Variables already set in the shell are never overridden.
- **Data paths.** Every generated artifact lives under a single `data/` folder,
  and run logs live in `logs/` alongside it. Both are resolved relative to the
  environment variable `CYBERSEC_SLM_DATA_ROOT`, which defaults to the current
  directory. That single variable is what lets you point the whole pipeline at a
  different working directory (a mounted volume, a synced folder) without touching
  code. The named paths are `RAW_DATA`, `CLEAN_DATA`, `FINAL_DATA`, `FLAGGED`,
  `DROPPED`, `STAGES`, and `LOGS`.
- **Logger.** One configured logger, using loguru when installed and the standard
  library otherwise. It writes an info-level stream to the console and a
  debug-level file to `logs/`. The log file path is scoped by process id
  (`pipeline.<pid>.log`). That per-process detail exists for a real reason: on
  Windows, worker processes each re-import this module and open their own file,
  and a shared path would make loguru's rotation fail because another process
  still holds the file open.
- **Integrity.** `sha256_file(path)` streams a file and returns its SHA-256 hex
  digest. This is what stamps the dataset fingerprint in the manifest.
- **JSONL input and output.** `json_loads` / `json_dumps` use orjson on the fast
  path and fall back to the standard library for the few cases orjson is stricter
  about. `iter_jsonl(path)` yields one dict per line and, crucially, yields a
  marker dict for a malformed line instead of crashing, so callers can count parse
  errors. `JsonlWriter` is a lazily-opened writer that creates no file until the
  first record is written, which keeps empty output files from littering the tree.

---

## 5. The command-line interface: `cli.py`

There is one console script, `cybersec-slm`, installed when you run `uv sync`.
`python -m cybersec_slm <command>` does the same thing. The CLI is a thin
argument parser that dispatches to the right stage. Imports are deliberately
lazy (done inside each branch) so that, for example, running `eda` never imports
the ingestion or dashboard machinery.

The commands:

| Command | What it does |
|---|---|
| `run [--sources X] [--workers N] [--resume] [--keep-raw] [--limit N] [--source-timeout S]` | Fetch and clean each source in parallel (the overlapped path), then a cross-source dedup pass. Stops after cleaning. |
| `all [--resume] [--keep-raw] [--limit N] [--no-auto-rebalance] [--source-timeout S]` | The full pipeline: ingest and clean, dedup, EDA gate, normalize. |
| `clean <sanitize\|dedup\|pii\|lang\|report\|balance>` | Cleaning diagnostics and one-off operations, not the production cleaning path. |
| `eda [--input P] [--no-enforce] [--no-auto-rebalance] [--profile]` | Compute metrics and apply the sufficiency gate. |
| `normalize [--input P] [--fresh] [--limit N]` | Map cleaned records onto the canonical schema and write the final dataset plus manifest. |
| `validate` | Check `data/clean/` records against the Pydantic schema without writing anything. |
| `source [--domains ...] [--mode datasets\|text\|both] [--dry-run] ...` | Discover new candidate sources through web search. |
| `synthetic-scan [--apply]` | Suggest which catalog rows look synthetic (a curation aid). |
| `flow [--dvc-push] [--no-enforce-eda]` | Run the same pipeline through Prefect (needs the orchestration extra). |
| `dashboard [--port N] [--headless]` | Launch the Streamlit monitor and explorer (needs the dashboard extra). |

Two flags show up on several commands and are worth understanding once:

- `--resume` skips sources that already finished fetching and cleaning in a prior
  run, and it picks the final dedup pass back up where it stopped. A fresh run
  (the default) resets that ledger so nothing is silently skipped.
- `--source-timeout` gives each source a wall-clock budget (default 1800 seconds).
  A source that hangs past its budget is abandoned so it cannot stall the whole
  run.

---

## 6. Stage 0: Sourcing (optional)

The sourcing stage proposes new sources for a human to review. It never fetches
anything, and nothing it finds reaches ingestion directly. It lives in
`src/cybersec_slm/sourcing/`.

The flow, driven by `run.py::discover`:

1. For each cybersecurity sub-domain, it runs a set of keyword searches through
   a self-hosted SearXNG instance. The keywords live in `sources/keywords.yaml`
   (an editable catalog, loaded by `catalog.py`, falling back to the built-in
   lists in `keywords.py` when the file is absent), one list per sub-domain, in
   two flavors: a `datasets` catalog (biased toward corpora and repositories) and
   a `text` catalog (biased toward articles, guides, and writeups). A query
   qualifier is appended to each keyword to push results toward the kind of page
   you want. Two independent caps bound a run: `--max-per-domain` (new rows per
   sub-domain) and `--max-total` (new rows across the whole run).
2. Each search hit becomes a candidate catalog row (`row.py` builds it, assigning
   the sub-domain and inferring the other fields). `classify.py` and the
   `DOMAIN_VOCAB` term lists help break ties on ambiguous results.
3. Any URL already in the catalog, or already seen earlier in this run, is
   dropped. `sheet.py` reads the existing links and appends survivors.
4. The survivors are always written to a review CSV under `logs/discovered/`, so
   even a live run leaves a record of exactly what was added. Unless you pass
   `--dry-run`, they are also appended to `sources/Sources.csv`.

The `search.py` module queries the SearXNG JSON API and raises a clear
`SearchError` when the instance is unreachable or has the JSON format disabled.
The base URL comes from `--searxng-url` or the `SEARXNG_URL` environment variable
(default `http://localhost:8080`); the instance must enable the JSON format
(`search: formats: [html, json]` in its `settings.yml`).

There is also a curation aid, `synthetic_scan.py`, exposed as
`cybersec-slm synthetic-scan`. It reads each catalog row's name, description,
category, and license and looks for words that suggest the source is
model-generated (strong terms like "synthetic", "llm-generated", "dpo", and
weaker terms like "instruction" or "q&a"). It only proposes. `--apply` writes
`Is Synthetic? = Yes` for high-confidence matches only; weak matches are always
left for a human. The point is a safety net over newly added rows, not an
authority. The authority stays the human-curated flag.

---

## 7. Stage 1: Ingestion

Ingestion downloads each source and converts it into one simple format: JSONL,
one JSON record per line, under `data/raw/<Sub-Domain>/<source>/`. It lives in
`src/cybersec_slm/ingestion/`. Because ingestion and cleaning are fused, the
ingestion code is driven by the parallel worker pool, not by a standalone
command.

### 7.1 The source catalog: `sources.py`

The corpus is curated entirely in one spreadsheet, `sources/Sources.csv`.
`sources.py` reads that CSV and turns each row into a *source descriptor*, the
small dict the fetch and scrape handlers understand. The catalog has 20 columns
(name, sub-domain, description, dataset link, sizes, line counts, license, a
synthetic flag, and so on), and header matching is case-insensitive so small
spelling differences do not break the mapping.

The interesting work is `_row_to_descriptor`, which decides what *kind* of source
each row is when the row does not say so explicitly. It looks at the URL and the
format and dispatches:

- HuggingFace dataset URL -> `hf`
- Kaggle dataset URL -> `kaggle`
- a `.pdf` (or an arXiv `/pdf/` link) -> `pdf`
- an HTML page or a "scraping" access method -> `website`
- a bare `.json` endpoint -> `feed`
- a GitHub URL -> `github`
- the NVD API host -> `api`
- a MITRE CWE XML-in-ZIP -> `xml`
- anything else with a direct file URL -> `url`

A few practical details live here. Slugs (used as folder names) are capped at 45
characters so the full `data/clean/<domain>/<slug>/<slug>.jsonl` path stays under
the Windows 260-character path limit. Sources are returned smallest-first by their
catalog size hint, so a run drains fast, small sources early and defers the
multi-gigabyte downloads. That gives you early progress instead of a run that
stalls for an hour on one big download.

`sources.py` also holds two functions used by the synthetic-source policy:
`source_identity(url)` collapses a URL to a stable identity (a HuggingFace or
Kaggle `/datasets/<org>/<name>` ref, or a normalized host and path), and
`synthetic_identities()` returns the identities of every catalog row flagged
synthetic. Matching on the dataset ref, not the folder slug, is what keeps two
different datasets that happen to share a slug cleanly separated.

### 7.2 The parallel orchestrator: `parallel.py`

This is the heart of a run. `run_ingest_clean` sets up a process pool (using the
`spawn` start method, which is what Windows requires) of fetch-only workers. Each
worker fetches one source, converts it to JSONL, and runs the light EDA gate. The
parent process is the consumer: as each source finishes, the parent cleans it
inline and sequentially, then deletes its raw folder (unless you pass
`--keep-raw`), and appends the source to the resume ledger
(`logs/completed_sources.txt`).

Why split it this way? Two reasons. First, cleaning uses heavy models (Presidio
for PII, a language identifier), and building those once in the parent is far
cheaper than building them once per worker. Second, fusing fetch and clean means a
source's raw data is deleted as soon as it is cleaned, so peak disk usage is
roughly one source's raw size, not the whole corpus.

The loop is built to survive trouble:

- A source that raises is resubmitted up to twice (`MAX_SOURCE_RETRIES`), then
  counted as failed.
- A source that runs past `source_timeout` is abandoned, and the pool is rebuilt.
- A broken process pool is caught, the survivors are re-queued, and the pool is
  rebuilt, up to `MAX_POOL_REBUILDS` times.
- Failed sources are never written to the resume ledger, so they retry on the
  next run.

On a fresh (non-resume) run, the function first wipes `data/clean/` and
`data/raw/`, resets the dedup checkpoint, and removes stale report files, so a new
build never inherits state from an old one.

`run_v2_pipeline` is the full sequence: `run_ingest_clean`, then the deterministic
cross-source dedup pass, then the deep EDA gate, then normalization. `run` stops
after dedup; `all` runs the whole thing.

### 7.3 The per-source worker: `worker.py`

`process_source` is a top-level, picklable function so it can run inside the
process pool. It handles one source end to end and is fully isolated: one bad
source returns a `status="failed"` dict instead of crashing the pool. The order
of operations inside a worker is exactly:

1. **License gate first.** Before anything is downloaded, `is_license_ok` checks
   whether the source's license clearly permits commercial training. A source
   that fails is marked `skipped`, logged, recorded, and never fetched.
2. **Fetch.** `_fetch_one` dispatches to the right handler by kind (see below).
3. **Light EDA gate.** `light_eda.assess_source` samples the fetched records and
   either rejects the source (moving it to `data/dropped/_rejected/` with a
   sidecar report) or annotates it with flags.
4. **Clean.** If the source passed, the worker returns the cleaned rows (cleaning
   itself is invoked here for the light-EDA-passing source).

The worker also caches the set of synthetic identities once per process rather
than re-reading the catalog for every source.

### 7.4 The license gate: `license_gate.py`

This is the strict admission control. A source is fetched only if its license
clearly permits unencumbered commercial use, and the gate is **default-deny**:
anything it does not recognize as clearly commercial is blocked.

Because the catalog's license column is free text and wildly inconsistent, the
gate works on keywords over the lowercased, whitespace-collapsed string. There are
two patterns, and the order matters. The deny pattern (non-commercial,
share-alike, GPL family, copyleft, proprietary, "all rights reserved", and so on)
is tested *before* the allow pattern (MIT, Apache, BSD, CC0, plain CC-BY-4.0,
public domain, US government works, MITRE, IETF). Testing deny first is what makes
a compound string like `CC BY-NC-SA 4.0` get correctly blocked even though it also
contains an allow substring.

Two pure functions do the work: `classify_license(raw)` returns
`(commercial_ok, reason)`, and `is_license_ok(descriptor)` adds the environment
kill switch. Enforcement is on by default; `CYBERSEC_SLM_ENFORCE_LICENSE_GATE=0`
turns it off for local development.

### 7.5 The light EDA gate: `light_eda.py`

This runs right after a source is fetched and before cleaning. Its job is to
instantly reject sources that are corrupted or structurally unusable, and to
annotate the rest with flags. It is deliberately fast (it samples at most 200
records) and conservative (a few bad records are expected and handled later by
cleaning; only a truly broken source is rejected).

A source is rejected if any of these is true: no JSONL files were produced, zero
valid records (all parse errors), more than 80% of records have no usable text, or
the median garbage-character ratio across the sample is above 0.50. A rejected
source is moved to `data/dropped/_rejected/` with a sidecar JSON report so the
decision is auditable.

For sources that pass, it attaches three kinds of flags: whether the source is
synthetic (by matching its identity against the flagged set), whether its license
looks risky, and whether the security-hazard scan found anything.

### 7.6 The hazard scanner: `hazard_scan.py`

A cybersecurity corpus legitimately contains exploit code, shellcode, and
payloads, so this scanner **flags but never auto-drops.** It looks for embedded
active content (`<script>`, `<iframe>`, `javascript:`), suspiciously long base64
blobs, shell-injection patterns in structured fields, and URLs that match known
malware-distribution patterns (bare-IP URLs, high-abuse TLDs, raw pastebin,
ephemeral file sharing). Findings are summarized by type in the light EDA report,
and records that need a human look are the ones that would go to `data/flagged/`.

### 7.7 The fetch adapters

Each source kind has a handler. They all convert their input into the same
`{source, url, license, text, ...}` JSONL shape and record a row in the ingest
log.

- **`fetch.py`** handles dataset platforms and file URLs (`hf`, `kaggle`,
  `github`, `url`). It picks the best file format by priority (parquet, then
  jsonl, then csv, and so on), groups sharded HuggingFace files so they
  accumulate into one output instead of overwriting each other, expands ZIP
  archives, and collapses a repo full of many small files into a single JSONL per
  source. Anything over the 5 GB cap is skipped but still recorded so it shows up
  in the final table. A GitHub repo URL is rewritten to its branch-archive ZIP; a
  `/blob/` URL becomes its raw-file equivalent.
- **`scrape.py`** handles PDFs (via PyMuPDF, one record per page), JSON feeds (via
  httpx and orjson), and the MITRE CWE XML-in-ZIP. It knows the shapes of a few
  specific feeds: MITRE ATT&CK STIX objects become readable technique records, and
  CISA KEV entries become readable vulnerability records, so the cleaning stage
  does not drop them as empty.
- **`scrape_html.py`** crawls openly-licensed websites. The actual crawl runs in a
  separate subprocess (`crawl_runner.py`) so its Twisted reactor never conflicts
  with the process pool. The crawler is Scrapy: it obeys `robots.txt`, stays on
  the same domain under an allow-prefix, strips boilerplate nodes (script, style,
  nav, footer, and so on), and writes one record per page. Pages under a minimum
  length are skipped. JavaScript-heavy sites can opt into Playwright rendering.
- **`fetch_nvd.py`** pulls the NVD CVE 2.0 API, paginating through every CVE and
  turning each into a readable text block (CVE id, severity, weaknesses,
  description, references). An API key is optional and only raises the rate limit
  (from a 6-second to a roughly 0.7-second sleep between pages).

### 7.8 Ingestion shared helpers: `common.py`

`common.py` holds the HTTP client (httpx with tenacity retries and exponential
backoff), the robust file readers, and the ingest log. `read_any` reads csv,
jsonl, json, parquet, xlsx, txt, and rule files (YARA, Sigma, YAML) into a
DataFrame, tolerating broken JSON, mixed encodings, and ragged rows. Large csv,
parquet, and jsonl files take a polars lazy fast path that streams to JSONL at
constant memory instead of loading the whole file into pandas. `enrich_df` adds
`source`, `url`, `license`, and a derived `text` column to every record so the
cleaning stage finds provenance no matter what the original schema looked like.

The `IngestLog` is a small SQLite table with one row per produced or skipped file
(size, row count, license, status, SHA-256). It is the provenance ledger and the
source of the final table shown at the end of a run. Inside a worker, a lightweight
`_Collector` buffers those rows in memory instead of touching the shared SQLite
file, and the parent replays them into the real log in one transaction.

---

## 8. Stage 2: Cleaning

Cleaning takes the raw JSONL and produces the cleaned corpus. It mirrors the
`data/raw/` layout into `data/clean/` (records that survive), `data/flagged/`
(behavioral anomalies for a human to review), and `data/dropped/` (structural,
duplicate, and language drops, each with a reason). A per-file report goes to
`logs/clean_report.csv`. It lives in `src/cybersec_slm/cleaning/`.

Every record flows through a fixed order. `pipeline.py::clean_files` is the loop.

### 8.1 Text mapping: `textmap.py`

The cleaning stages all operate on a `text` field, but datasets keep their
original column names (`{question, answer}`, `{instruction, output}`,
`{body, label}`, and so on). `to_text` builds a `text` value by pulling recognized
natural-language columns. It tries, in order: an existing `text` field, an
explicit hint, list-of-turns chat shapes (ShareGPT `conversations`, OpenAI
`messages`), known multi-column combos, then single prose columns by confidence.

Two deliberate choices matter. System prompts in chat data are skipped, because a
repeated multi-hundred-token system prompt across 100,000 rows both bloats the
corpus and makes near-dedup falsely collapse distinct exchanges that share the
prefix. And pure feature tables (malware PE features, IDS flows, label-only rows)
have no prose column, so `to_text` returns `None` and the record is excluded from
the text corpus rather than turned into junk text.

### 8.2 Sanitize: `sanitize.py`

The first transform fixes structural problems. It repairs mojibake (ftfy when
available, otherwise a latin1/utf8 heuristic), normalizes unicode to NFC, strips
control characters, collapses runs of whitespace and blank lines, and normalizes
date-ish fields to ISO-8601. It normalizes fields that already exist but never
fabricates missing provenance fields, because the normalize stage supplies those
defaults later. It returns `(record, changed)` so the pipeline can count how many
records it touched.

### 8.3 Anomaly check: `anomaly.py`

`classify(record)` sorts each record into one of three buckets:

- **structural** means drop it. This covers a missing, empty, or non-string text
  field, a parse error, or text shorter than the 50-character floor after
  sanitizing.
- **behavioral** means flag it for review, never silently drop it. This covers
  content oddities a human should look at: extreme length, a high ratio of
  garbage (non-text) characters, heavy repeated lines, or a single token
  dominating the text.
- **clean** means continue.

The pipeline uses this to route records: structural to `dropped/`, behavioral to
`flagged/`. There is a small extra count here, `struct_fixed`, which records how
often sanitize rescued a record that would otherwise have been a structural drop.

### 8.4 Dedup: `dedup.py`

The `Deduper` does exact and near-duplicate detection. Exact is a SHA-256 of the
normalized text (lowercased, whitespace-collapsed), which is effectively free.
Near-duplicate uses MinHash plus LSH, with datasketch when installed and a
compact pure-Python MinHash with banded LSH as a fallback so it never hard-depends
on the library.

Two things about how dedup is actually used in production. First, the per-source
workers run with the deduper **disabled**, because cross-source deduplication is a
global concern that runs once, later, in the parent (see 8.7). Second, the
production cross-source and normalize passes run **exact-only**: byte-identical
records are removed, but fuzzy near-duplicates are kept on purpose. Near-dup
matching at the tuned Jaccard threshold of 0.65 collapsed too many
similar-but-distinct cyber records (templated CVE text, MITRE technique
descriptions, log lines), so the near-dup tier is available as an on-demand
diagnostic (`cybersec-slm clean dedup`) rather than a default filter. The MinHash
machinery and the 0.65 threshold are fully built and can be re-enabled without
reprocessing.

The exact-hash set can be saved and loaded as JSON (not pickle, deliberately,
because deserializing an untrusted pickle would be a code-execution risk). That is
what makes the cross-source pass resumable.

### 8.5 PII redaction: `pii.py`

The `Redactor` strips personally identifying information, replacing each span with
a typed placeholder like `<EMAIL_ADDRESS>`. It uses Microsoft Presidio (which runs
spaCy NER plus rules) when installed, and a regex fallback for the most common
identifiers (email, US SSN, credit card validated with the Luhn check, IPv4,
phone) otherwise. There is a size guard: because Presidio's cost grows with text
length, oversized payloads (over 10,000 characters by default, and often just
structured blobs with no prose PII anyway) skip Presidio and take the linear regex
path so a few huge records cannot stall the whole pass.

The honest limits of this on a security corpus (internal hostnames, private IPs,
service-account identifiers, API keys) are documented separately and handled by a
sampled manual review. Those were treated as explicit exceptions, not silently
ignored.

### 8.6 Language filter and translation: `langfilter.py`, `translate.py`

`LangFilter` detects the language, preferring fastText's lid.176 model, then
langdetect, then a standard-library heuristic (script ranges plus English
stopword hits). The drop policy is conservative: a record is only considered
non-allowed on a *confident* non-English detection. Uncertain or unknown results
are kept, so the fallback never throws away text it simply failed to identify.
There is a confidence floor for fastText so garbled text (an obfuscated phishing
email, say) is not mislabeled non-English.

When text is confidently non-English, the pipeline does not drop it. It sends it
to the `Translator`, which renders it into English and keeps it. Only genuinely
untranslatable text is dropped. The translator prefers deep-translator's Google
backend (online, no model download, with chunking for long text), then
argostranslate (fully offline). It is defensive about the free Google endpoint: a
per-call timeout, a cap on how many chunks one record can fan out into, and a
circuit breaker that disables the online backend after several consecutive
failures so a rate-limited endpoint cannot hang the whole run. An operator kill
switch (`CYBERSEC_SLM_TRANSLATE=off`) skips online translation entirely and drops
non-English instead.

### 8.7 The cross-source dedup pass

After the whole worker pool drains, `final_global_dedup` makes one pass over
`data/clean/` to catch duplicates shared across sources. It is deterministic:
files are processed in sorted order, so which of two cross-source duplicates
survives ("first wins") is stable across runs. It is checkpointed: the exact-hash
set and the list of finished files are written periodically, so `--resume`
restarts an interrupted pass where it stopped instead of from zero. As noted
above, this pass is exact-only by policy.

### 8.8 The `clean` diagnostics command

`cybersec-slm clean <action>` is not the production path (that is the worker). It
is a debugging aid. `sanitize`, `dedup`, `pii`, and `lang` each run a single
transform in isolation into `data/_stages/<action>/` so you can inspect what one
step does. `report` recounts the existing clean, flagged, and dropped trees.
`balance` reports per-domain record counts and can optionally cap or downsample.

---

## 9. Stage 3: The EDA sufficiency gate

This stage is where exploratory data analysis stops being a passive report and
becomes an enforcement point. It lives in `src/cybersec_slm/eda/`.

### 9.1 Metrics: `metrics.py`

`compute_metrics` makes one streaming pass over the cleaned corpus and returns:
total volume, per-sub-domain counts and distribution, the worst single-source
concentration within each sub-domain, text-quality stats (average and median
tokens and characters), an exact-duplicate rate, and a topic-balance number (the
coefficient of variation across sub-domain counts). It is pure standard library so
it stays cheap to run on every batch.

### 9.2 Thresholds: `config.py`

All the thresholds live here and are all overridable by environment variable. The
defaults are deliberately permissive so a small local build passes. The key ones:
minimum total records (50), minimum records per sub-domain (5), maximum
single-source share (0.60), maximum drift (0.25), maximum duplicate rate (0.40),
minimum average tokens (5), maximum topic coefficient of variation (1.5), and
minimum sub-domain share (0.01).

### 9.3 The gate: `pipeline.py`

`run_eda` computes the metrics, computes drift against the previous run (the
largest change in any sub-domain's share), evaluates the gate, generates
feedback, and persists a versioned `logs/eda/run-<timestamp>.json` plus a
`latest.json`. The versioned history is append-only so drift is auditable across
iterations.

The gate has two severities, and the distinction is the whole point:

- A **blocker** stops the run and loops back to ingestion. In the current code the
  only blocker is the total-volume floor: fewer than the minimum total records.
- A **warning** is logged and tracked but does not stop the run. Warnings cover
  single-source concentration above the ceiling, thin sub-domains, a high
  duplicate rate, low average tokens, drift, a high topic coefficient of
  variation, and any sub-domain below the minimum share.

Source concentration is intentionally a warning rather than a blocker. Hard-
blocking it would either deadlock (a sub-domain with a single source can never be
un-concentrated by capping) or force data destruction (capping a 31,000-record CVE
source down to match a 34-record PDF would delete a lot of genuine data). The real
remedy is adding sources at ingestion time, which the feedback section calls out.
Operators who do want to rebalance can opt in with `clean balance --source-share`.

The feedback section (`_generate_feedback`) turns the metrics into advice: which
sub-domains are under-represented and how many records they need for balance,
which are over-represented and a suggested cap, quality concerns, and top-level
recommendations. This is what makes the gate actionable rather than just a verdict.

There is an optional auto-rebalance step that caps over-represented sub-domains and
re-validates, but it is **off by default**. On a real build it silently deleted
tens of thousands of already-cleaned records to hit the topic-CV target, and since
over-representation is only ever a warning, leaving the data in place cannot halt
the run anyway. Turn it back on deliberately with `EDA_AUTO_REBALANCE=1`.

A blocker with enforcement on raises `SufficiencyError`, which halts the pipeline
so you loop back to ingestion. `--no-enforce` makes the whole thing report-only.

---

## 10. Stage 4: Normalization

Normalization maps every surviving record onto the canonical 22-field schema and
produces the release. It lives in `src/cybersec_slm/normalize/`. The orchestrator
is `pipeline.py::Normalizer`, and each record flows through this chain.

### 10.1 The canonical schema: `schema.py`

`CanonicalRecord` is a Pydantic v2 model with `extra="forbid"`, which means any
unexpected field is a hard validation error rather than silent drift. The 22
fields are grouped by who fills them:

| Group | Fields | Filled by |
|---|---|---|
| Identity | `id` (uuid4), `content_hash` (sha256 of text) | normalize |
| Content | `text` | cleaning, then normalize |
| Provenance | `source`, `source_url`, `license`, `origin_format` | ingestion |
| Auto-computed | `lang`, `token_count`, `char_count` | normalize |
| Pipeline meta | `pipeline_version`, `collected_at` | normalize |
| Labels | `source_file`, `record_type`, `domain_name`, `subdomain_name`, `domain_label`, `subdomain_label` | normalize (the two integer labels are `-1` placeholders) |
| Annotation | `safe_unsafe`, `confidence`, `instruction`, `reviewed_by` | downstream (null placeholders) |

The design principle is that each field is owned by exactly one stage and cannot
depend on a pending annotation stage. Anything the pipeline can compute
deterministically (hashes, counts, domain names) is filled in. Fields owned by the
downstream labeling and annotation teams get explicit, typed placeholders: the
weak-supervision integer labels are `-1` (ABSTAIN), and the human-annotation
fields are `null`. That way the record shape is fixed end to end, and the schema
acts as a precise contract between teams without exposing any collection-pipeline
internals.

The 12 canonical domains are: Application Security, Cloud Security, Cryptography,
Data Security and Privacy, Governance Risk and Compliance, Identity Access and
Management, Incident Response and Forensics, Network Security, Penetration
Testing, Security Operations, Threat Intelligence, and Vulnerability Management.
`resolve_domain` maps a raw domain string (often a folder name) onto the canonical
name and its schema sub-domain code, tolerating spelling variants through an
alias table. Two tracks were retired and are folded onto merge targets by that
table: Malware Analysis folds into Threat Intelligence, and Quantum and
post-quantum cryptography fold into Cryptography. The top-level `domain_name` is
always `CYBERSEC`; there is no separate quantum domain. Post-quantum material is
tracked within the Cryptography sub-domain.

### 10.2 Mappers: `mappers.py`

A mapper turns one cleaned record (whatever its original schema) into the
intermediate text-and-provenance dict the enrichment step expects. There are two
concrete strategies. `ProseMapper` handles records whose payload is already
natural-language text. `StructuredMapper` handles feature and table rows by
rendering the salient columns into a readable "key: value" sentence, so a table
row still carries text instead of being dropped. Both strip boilerplate lines
(cookie notices, "read more", copyright footers) and normalize whitespace.

Mappers register themselves in a registry. `get_mapper` picks one by source name,
and for an unknown source it dispatches by record shape (prose if there is usable
text, structured otherwise) and fires a first-sight alert the first time it sees
that source, counting it as unmapped for the report. Nothing is dropped just for
being unfamiliar.

### 10.3 Enrichment: `enrich.py`

`build_record` takes the mapper output and fills everything else in the 22-field
contract: a fresh uuid4 `id`, the `content_hash`, the detected `lang` (via
langdetect, seeded for determinism, defaulting to English because cleaning has
already translated non-English text), the token and character counts, the pipeline
version and an ISO-8601 UTC timestamp, the resolved domain and sub-domain names, a
best-effort `record_type` (cve, log, advisory, playbook, doc, or article, guessed
from the source identifiers), and the downstream placeholder fields. It returns a
plain dict ready to validate.

### 10.4 The synthetic filter: `synthetic.py`

Before a record is even mapped, the `SyntheticFilter` checks whether it belongs to
a source flagged synthetic in the catalog. Synthetic sources are still fetched,
cleaned, and counted by the EDA gate, but their records are held out of the final
corpus. The decision is a curated-flag lookup, not content analysis: it matches
the record's URL back to a flagged catalog row through the same stable
`/datasets/<org>/<name>` identity the catalog uses. Excluded records are diverted
(not deleted) to an auditable `excluded_synthetic.jsonl` sink, and their volume is
reported separately.

### 10.5 Validation, dedup, and failure tracking: `dedup.py`

After enrichment, the record is validated against `CanonicalRecord`. An invalid
record is written to a **metadata-only** `rejected.jsonl` (the raw text is only
included when `CYBERSEC_SLM_DEBUG_REJECTS=1`, to avoid a second PII leak in
diagnostic logs). Each reject is categorized (mapper mismatch, dirty data, or
ambiguous), because a spike in mapper mismatches often signals upstream schema
drift or manipulation. A `FailureTracker` counts rejects per source, warns once at
5, and hard-pauses a source at 20. A paused source's remaining records are skipped
so they go back to cleaning rather than flooding the logs.

A record that validates goes through the near-duplicate check
(`NearDuplicateIndex`). As with the clean stage, this runs exact-only in
production, so byte-identical records are removed and similar-but-distinct ones are
kept. Every record's best-match score is still logged to `dedup_scores.jsonl`, so
the near-dup threshold can be re-tuned later without reprocessing. Duplicates go to
`duplicates.jsonl`. Survivors are appended to `dataset.jsonl`, and the index is
updated. The index can rebuild itself from an existing `dataset.jsonl`, which is
what makes a normalize run resumable.

### 10.6 The provenance manifest: `manifest.py`

Every release ships with `manifest.json`, a "datasheet for datasets". It records
the record count, unique content hashes, token and character totals, breakdowns by
domain, sub-domain, source, license, origin format, record type, and language, an
EDA snapshot, the pipeline version, the git commit, and a SHA-256 of the dataset
file. This is what lets a bad batch be scoped and rolled back surgically instead of
discarding the whole corpus. The downstream teams are never handed a blob with no
pedigree.

---

## 11. Governance and security controls

Pulling the security story together, here is what runs at each stage and why. The
common thread is that every layer assumes its input could be hostile or low
quality, and pushes the response toward something traceable, reversible, and
auditable.

| Stage | Controls |
|---|---|
| Sourcing | Discovered sources are written to the catalog for human review, never fetched directly. A dry-run mode plus a CSV audit artifact record exactly what was added. |
| Ingestion | A default-deny commercial-license gate; a light EDA gate that rejects broken sources and flags synthetic, license-risk, and hazard findings; per-source process isolation; a provenance ingest ledger. |
| Cleaning | PII redaction (Presidio with a regex fallback), with documented blind spots and a sampled manual review; anomaly quarantine to `flagged/`; auditable drop reasons in `dropped/`. |
| EDA | A blocking sufficiency gate (volume), a tracked source-concentration warning with feedback, drift detection, and a versioned append-only run history. |
| Normalization | Synthetic-source exclusion; strict schema validation with closed enums; metadata-only reject logs; per-source failure escalation; per-record near-dup scores; content hashing. |
| Release | A provenance manifest (the datasheet) and DVC-versioned releases for scoped rollback. |
| CI and supply chain | Secret scanning over the full git history (gitleaks), dependency auditing (pip-audit), and a least-privilege CI token. |
| Deployment | Immutable ECR image tags with scan-on-push; an S3 bucket with public access blocked, encryption, and versioning; a least-privilege IAM task role; secrets injected at runtime, never baked into the image. |

---

## 12. Orchestration, versioning, and deployment

### 12.1 Prefect: `orchestration/flows.py`

`cybersec-slm flow` runs the same pipeline through Prefect. The flow is a thin
wrapper: it adds scheduling, per-source isolation with retries and timeouts,
secret loading, and an optional DVC snapshot, but the real work still lives in the
ingestion, cleaning, eda, and normalize modules. Prefect is optional. The module
imports cleanly without it, because the `@flow` and `@task` decorators degrade to
no-ops when Prefect is absent, which keeps the plain helper functions unit-testable.
`load_secrets` best-effort hydrates API keys from AWS Secrets Manager when
prefect-aws is configured, and falls back to `.env` otherwise.

### 12.2 DVC: `dvc.yaml`

`dvc repro` rebuilds the corpus end to end and versions the outputs to an S3
remote, with the EDA and normalize reports tracked as metrics. Versioned releases
are what let a bad batch be rolled back or scoped without discarding the whole
dataset.

### 12.3 Docker and AWS: `Dockerfile`, `infra/`

The `Dockerfile` builds a Python 3.13 image, ordered so that editing code rebuilds
only the fast final layer, not the heavy dependency and browser layers. It
installs Chromium for the crawler, runs as an unprivileged user, writes everything
under a mounted `/work` volume, and reads secrets from the environment at runtime.

The `infra/` Terraform skeleton provisions the AWS side: an ECR repository with
immutable tags and scan-on-push, an S3 bucket that is versioned, encrypted, and
has public access blocked, a least-privilege ECS task role (read/write only the
one data bucket, read only the named secrets), Secrets Manager entries whose
values are set out of band and never in Terraform state, an ECS Fargate cluster,
and a CloudWatch log group. The intended runtime is a Prefect ECS push work pool
pointed at that cluster and role.

---

## 13. The dashboard

The dashboard is a local-first Streamlit app, an optional extra so a plain install
stays lean. It lives in `src/cybersec_slm/dashboard/`. Its design principle is a
strict separation between reading and rendering.

- **`data.py`** is the only code that touches the pipeline's artifacts. It is pure
  functions returning plain Python, with no Streamlit import, so every function is
  unit-tested headlessly. Paths resolve through the data root on each call, which
  is what makes the same functions serve a hosted deploy when you point the root at
  a synced location. Every function tolerates missing artifacts by returning empty
  values, so a fresh checkout does not crash the UI. This module computes the run
  status and phase, the live progress, the EDA history, the stage reports, the data
  funnel (raw to cleaned to final), a loss breakdown ("where did my data go"), and
  the paged dataset view with filter and substring search.
- **The pages** are presentation only. **Pipeline** shows the live run strip, the
  EDA sufficiency gate, trends over past runs, the per-source table, stage
  reports, and the manifest. **Dataset** searches and filters the final corpus plus
  the rejected and duplicate sinks. **Agent** is a chat box.
- **`control.py`** is a small local control plane: it can start `cybersec-slm all`
  as a detached subprocess, stop the process tree, and reset (wipe all pipeline
  output) for a clean slate. It acts only on the machine running the dashboard,
  because this is a local-first tool. It has no Streamlit import, so it too is
  unit-testable.
- **The agent** is deliberately the most locked-down surface. `agent_tools.py`
  exposes exactly seven read-only tools: pipeline status, EDA status, manifest
  summary, source table, stage reports, a dataset search, and a rejected/duplicate
  preview. Each one wraps `data.py` and trims its output to fit an LLM context
  window. `agent_client.py` runs the tool-calling loop against NVIDIA NIM through
  the OpenAI-compatible SDK, bounded to six iterations and a 60-second per-request
  timeout. The system prompt tells the model it can only read. There is no tool
  that can trigger a run, retry a source, or write to disk, so broadening access to
  the agent does not expand the pipeline's attack surface. Tool exceptions become
  error results the model can see rather than crashes, and a missing API key
  degrades to setup instructions.

---

## 14. Testing and CI

The tests live in `tests/`, one module per stage, run with `uv run pytest`. Two
conventions keep them fast and hermetic. First, they avoid heavy or networked
imports so they run headlessly against a disposable data root (a temporary
directory pointed at by `CYBERSEC_SLM_DATA_ROOT`). Second, they lean on the
graceful-degradation design: an uninstalled optional dependency (Presidio,
fastText, Streamlit, the OpenAI SDK) makes the relevant test skip or mock rather
than fail.

Continuous integration (`.github/workflows/ci.yml`) runs secret scanning over the
full git history with gitleaks, a dependency vulnerability audit with pip-audit,
ruff linting, and the test suite. The deploy workflow builds and pushes the image.
A pre-commit config runs the local secret and lint hooks before a commit lands.

---

## 15. Configuration reference

Every API key is optional for a basic local run and is read from `.env`
(auto-loaded; shell environment wins).

| Variable | Used by | Required? |
|---|---|---|
| `NVD_API_KEY` | NVD CVE feed (higher rate limit) | optional |
| `KAGGLE_API_TOKEN` | Kaggle sources | only for Kaggle sources |
| `SEARXNG_URL` | the `source` stage (SearXNG discovery) | optional (default `http://localhost:8080`) |
| `CYBERSEC_SLM_DATA_ROOT` | all stages (where `data/` and `logs/` go) | optional |
| `CYBERSEC_SLM_ENFORCE_LICENSE_GATE` | the ingestion license gate (on by default; `0` disables) | optional |
| `CYBERSEC_SLM_TRANSLATE` | the cleaning translate step (`off` skips online translation) | optional |
| `CYBERSEC_SLM_PII_MAX_CHARS` | the PII size guard (default 10,000) | optional |
| `CYBERSEC_SLM_DEBUG_REJECTS` | include raw text in reject logs | optional |
| `NVIDIA_API_KEY` | the dashboard Agent page | only for the Agent page |
| `CYBERSEC_SLM_NIM_MODEL`, `CYBERSEC_SLM_NIM_BASE_URL` | Agent model and endpoint overrides | optional |
| `EDA_MIN_TOTAL`, `EDA_MAX_SOURCE_SHARE`, `EDA_MAX_DRIFT`, and the other `EDA_*` thresholds | the sufficiency gate | optional |

---

## 16. Data and log layout

All generated corpus artifacts live under one `data/` folder, with run logs in
`logs/` alongside it. Both resolve relative to `CYBERSEC_SLM_DATA_ROOT` and are
git-ignored.

| Folder | Produced by | Purpose |
|---|---|---|
| `data/raw/` | ingestion | normalized JSONL per source (deleted as each source is cleaned, unless `--keep-raw`) |
| `data/clean/` | cleaning | the cleaned corpus that feeds the EDA gate |
| `data/flagged/` | cleaning | behavioral anomalies for human review |
| `data/dropped/` | cleaning and dedup | removed records, each with a reason |
| `data/final/` | normalization | `dataset.jsonl`, `manifest.json`, and the reject / duplicate / dedup-score / synthetic sinks |
| `logs/` | all stages | run logs, EDA history, clean and normalize reports, the provenance ledger, the resume ledger, and the dedup checkpoint |

---

## 17. How to run it

Requires Python 3.13 or newer and [uv](https://docs.astral.sh/uv/).

```bash
cp .env.example .env                    # API keys (all optional for a basic run)
uv sync                                 # install the pipeline
uv run playwright install chromium      # the browser for the website crawler
uv run cybersec-slm all                 # ingest -> clean -> EDA gate -> normalize
uv run cybersec-slm all --resume        # re-run without re-downloading finished sources
```

That writes the finished corpus to `data/final/dataset.jsonl`. To watch a run
live, browse the result, and ask the built-in agent about the corpus:

```bash
uv sync --extra dashboard               # installs Streamlit
uv run cybersec-slm dashboard           # http://localhost:8501
```

To run one stage at a time:

```bash
uv run cybersec-slm run                 # ingest + clean each source -> data/clean/
uv run cybersec-slm eda                 # validate + sufficiency gate -> logs/eda/
uv run cybersec-slm normalize           # canonical dataset -> data/final/
```

For the AWS path (Prefect Cloud plus ECS Fargate), see
[operations/deploy.md](operations/deploy.md); for versioned releases with DVC, see
[operations/dvc.md](operations/dvc.md).

---

## 18. Known limits worth naming

- **PII on a security corpus.** The automated pass does not catch internal
  hostnames, private IP ranges, service-account identifiers, or API keys. Those
  are handled by a sampled manual review and are documented in
  [pii_limitations.md](pii_limitations.md). Widening this coverage is planned.
- **Near-duplicate detection is off by default.** The exact tier runs; the fuzzy
  MinHash tier is on-demand because at 0.65 it over-collapsed templated cyber
  content. Semantic (embedding-based) deduplication is a planned addition for
  catching paraphrased near-duplicates that lexical hashing misses.
- **The corpus is still filling in.** The catalog holds 192 sources, and the
  distribution is uneven (Cryptography, which absorbs the post-quantum track, is
  by far the largest by source count). The sufficiency gate surfaces this as a
  concentration warning with feedback, and the near-term work is adding vetted
  sources to the thin sub-domains until the corpus is balanced across all twelve.
- **Documentation drift.** As noted in Section 3, some older docs and `dvc.yaml`
  still reference a source allowlist that is no longer in the code.
