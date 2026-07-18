# Following the data through the pipeline

This is the journey of one piece of data, from a name on a list to a finished line
in the training set. Read it top to bottom and you are walking the same path the
data walks. Along the way it names the libraries doing the work and explains how
each step actually happens under the hood.

The whole trip is run by one command, `cybersec-slm all`, which calls
`run_v2_pipeline` in
[`ingestion/parallel.py`](../src/cybersec_slm/ingestion/parallel.py). The stages run
in strict order with no overlap, and each writes under a data root that
[`core.py`](../src/cybersec_slm/core.py) resolves from `CYBERSEC_SLM_DATA_ROOT`
(the current folder by default). Everything logs through `loguru`, and each run
gets its own `logs/pipeline.<pid>.log`.

## It begins as a name on a list

At the start, the data does not exist yet, not as anything you can read. What
exists is a row in a catalog, [`sources/Sources.csv`](../sources/Sources.csv). Think
of that row as a note to self: "there is a dataset over here, this is its link, this
is roughly how big it is, and this is the license it comes under."

The catalog is a plain CSV. Each row carries, among about twenty columns:

```
Name, Sub-Domain, Description, Dataset Link, Category, Original Format,
Original Size (MB), JSONL Size (MB), Total Lines, License, Is Synthetic?, ...
```

So one row looks roughly like:

```
Name:            aws-cloudtrails-dataset-from-flaws-cloud/dec12_18features
Sub-Domain:      Cloud Security
Dataset Link:    https://www.kaggle.com/datasets/nobukim/aws-cloudtrails-...
Original Format: csv
License:         Apache-2.0
```

Technically, `sources.load_descriptors`
([`ingestion/sources.py`](../src/cybersec_slm/ingestion/sources.py)) reads that CSV
with `pandas` and turns each row into a *descriptor*, a small dict that says what
kind of source it is and how to fetch it. It sorts them smallest first using each
row's catalog size hint, so the quick sources drain early and the multi gigabyte
ones defer. If you passed `--max-source-gb`, any source whose catalog size is over
the cap is filtered out of the list right here, before a single byte is downloaded.

## Before knocking, it checks the lock

The pipeline does not just start downloading. For each source it stops and asks one
question first: are we actually allowed to train on this, commercially, no strings
attached?

That check is `license_gate.is_license_ok`
([`ingestion/license_gate.py`](../src/cybersec_slm/ingestion/license_gate.py)). It
is a set of compiled regular expressions run over the lowercased, whitespace
collapsed license string, and it is default deny. The deny patterns (non commercial,
copyleft, share alike, and so on) are tested before the allow patterns, so a
"CC BY-NC-SA" cannot slip through on the "CC BY" part. Anything not clearly cleared
for commercial use is turned away here and never downloaded. The refusal is recorded
so you can see later exactly what was skipped and why.

Only the sources that pass this check move on.

## The download, and the great flattening

Now a worker goes out and actually fetches the source. All of this happens in
parallel: the parent hands the descriptors to a `ProcessPoolExecutor`, and each
source is fetched in its own OS process by `worker.process_source`
([`ingestion/worker.py`](../src/cybersec_slm/ingestion/worker.py)). That isolation
matters, because a hung download or a crashing parser takes down only its own
worker, and the parent just records a `failed` or `timed_out` status and moves on.

What the worker does depends on the kind of source, and each kind has its own client:

- **Hugging Face** datasets come down through the `huggingface-hub` client, and
  **Kaggle** datasets through the official `kaggle` client.
- **Plain files and the NVD CVE feed** are pulled over HTTP with `httpx`, wrapped in
  `tenacity` retries so a flaky endpoint gets a few attempts before giving up. The
  NVD feed is a paginated REST API, walked page by page.
- **PDFs** are opened and read page by page with `pymupdf`.
- **Websites** are crawled with `scrapy` plus `scrapy-playwright`, run as a separate
  subprocess (via [`crawl_runner.py`](../src/cybersec_slm/ingestion/crawl_runner.py))
  so Scrapy's Twisted reactor never tangles with the parent process. `playwright`
  drives a real browser for pages that need JavaScript to render, and `selectolax`
  parses the HTML that comes back.

Here is the key move. Whatever shape the source arrived in, the worker flattens it
into one format: JSONL, one record per line. Tabular files (CSV, Parquet, Excel) are
read with `polars`, `pyarrow`, and `pandas` (with `openpyxl` behind Excel) and each
row becomes a line. Almost valid JSON is salvaged with `json-repair`, records are
serialized fast with `orjson`, and garbled text is repaired with `ftfy`. From this
point on the pipeline stops caring where anything came from and treats every source
the same way. The flattened files land in `data/raw/<topic>/<source>/…jsonl`, with
the originals kept beside them.

A raw record keeps whatever columns the original had, plus three fields the fetcher
stamps on every record so provenance is never lost: `source`, `url`, and `license`.
So a record from a chat-style dataset comes out looking like this (one JSON object
per line):

```json
{
  "system": "You are a security expert.",
  "user": "Explain a reflected XSS attack.",
  "assistant": "A reflected XSS occurs when ...",
  "source": "AlicanKiraz0",
  "url": "https://huggingface.co/datasets/AlicanKiraz0/...",
  "license": "MIT"
}
```

The fields differ from source to source (a CVE feed, a PDF, and a chat dataset all
have different columns). What is constant is the container: newline-delimited JSON,
one record per line, with `source` / `url` / `license` attached.

## A quick sniff test at the door

The moment a source is downloaded, it gets a fast once over by
`light_eda.assess_source`
([`ingestion/light_eda.py`](../src/cybersec_slm/ingestion/light_eda.py)). This is a
cheap, dependency light check: is there real content here, how long are the records,
does it look like junk, and it also annotates flags (is this a synthetic source, any
license risk, any security hazard hits). If the source fails, the whole folder is
moved into `data/dropped/` with a sidecar report. If it passes, it waits.

As each worker finishes, the parent replays its buffered rows into a small SQLite
database, `logs/ingest_log.sqlite` (plain `sqlite3`), and appends the source to a
resume ledger, `logs/completed_sources.txt`. That ledger is what `--resume` reads to
skip sources already fetched. By the time this stage ends, every source on the list
has been tried, and each one is on the record as fetched, skipped for license,
failed, timed out, or rejected as empty.

## Now the real cleaning, one record at a time

With everything downloaded, the pipeline reads back through every record and cleans
it. The record chain is `clean_files` in
[`cleaning/pipeline.py`](../src/cybersec_slm/cleaning/pipeline.py), and each record
walks the same short hallway with doors it can be pushed through:

1. **Build the text** (`textmap.to_text`): assemble a readable `text` field from the
   record's prose columns. Some records are pure feature tables with no prose at all;
   those have nothing for a language model to read, so they are set aside here. This
   is the single biggest reason the record count drops so far, since the largest
   tabular datasets have no words to keep.
2. **Tidy it** (`sanitize.sanitize_record`, using `ftfy`): fix encoding damage,
   normalize whitespace, repair the obvious.
3. **Inspect it** (`anomaly.classify`): a structurally broken record (empty,
   unparseable, far too short) is dropped to `data/dropped/`; a behaviorally odd one
   (heavy repetition, garbage, strange length) goes to `data/flagged/`, the "let a
   human look" pile rather than the trash.
4. **Mask personal data** (`pii.Redactor`): Microsoft's `presidio-analyzer` and
   `presidio-anonymizer`, backed by the `en_core_web_lg` spaCy model, find names,
   emails, and other PII and mask them in place.
5. **Handle language** (`langfilter` and `translate`): the language is identified
   with `fasttext-predict` (with `langdetect` as a fallback). If the text is
   confidently not English, it is translated with `deep-translator` and kept, rather
   than dropped. Only genuinely untranslatable text is dropped.

Whatever survives the hallway is written to `data/clean/`, mirroring the raw layout.
The record still carries its original fields, but now it has a real `text` field
built from the prose (with PII already masked inside it), plus `_text_field` naming
which column the text came from, and `_orig_lang` if it was translated:

```json
{
  "system": "You are a security expert.",
  "user": "Explain a reflected XSS attack.",
  "assistant": "A reflected XSS occurs when ...",
  "source": "AlicanKiraz0",
  "url": "https://huggingface.co/datasets/AlicanKiraz0/...",
  "license": "MIT",
  "text": "User: Explain a reflected XSS attack.\nAssistant: A reflected XSS ...",
  "_text_field": "assistant"
}
```

Every record that was pushed through a side door carries the reason with it. A
dropped or flagged record is the original record plus five underscore-prefixed
fields, so the file itself explains why it is there:

```json
{ "...": "...original record...",
  "_sub_domain": "Cryptography", "_source": "darkknight25",
  "_file": "Cryptography/darkknight25/dataset.jsonl",
  "_stage": "anomaly", "_reason": "structural: text under 50 chars" }
```

The heavy models (Presidio, the spaCy model, fastText) are built once per worker
process and reused across every source that worker handles, because each one costs
seconds and hundreds of megabytes to load.

There is one more sweep after every source is cleaned. Two different sources often
carry the identical record (the same CVE text copied around, the same log line), so
`final_global_dedup` makes a single pass over the whole cleaned corpus. It uses the
`Deduper` from [`cleaning/dedup.py`](../src/cybersec_slm/cleaning/dedup.py), which is
built on `datasketch` (MinHash and LSH) but here runs in exact only mode: it removes
records that are byte for byte identical after normalization and keeps merely similar
ones, because in security data a lot of records look alike without being copies. It
walks files in sorted order so "which duplicate survives" is deterministic, and it
checkpoints its hash set so an interrupted pass resumes instead of restarting. Every
removed record still goes to the dropped pile with a reason, so nothing vanishes
silently.

## The checkpoint: is this corpus actually good enough?

Now the pipeline stops and measures what it has built. `run_eda`
([`eda/pipeline.py`](../src/cybersec_slm/eda/pipeline.py)) computes the metrics with
plain standard library statistics (`collections`, `statistics`): total volume,
records per topic, how concentrated each topic is in a single source, average tokens
per record, the exact duplicate rate, and a topic balance number. It also compares
the topic mix against the previous run to measure drift.

Then `evaluate_gate` turns those numbers into violations. Most are warnings, noted
and passed. There is one hard blocker: if the total volume is below the minimum, the
pipeline raises `SufficiencyError`, stops right here, writes down which topics are
thin and where to find more sources, and sends you back to ingestion. It will not
ship a starved dataset. Auto rebalancing (capping an over represented topic) exists
but is off by default. Every run, pass or fail, is saved as a dated
`logs/eda/run-<timestamp>.json` so you can diff this run against the last.

If the corpus clears the bar, it moves on.

## The final shaping

The records that made it here are close to done but still in slightly different
shapes depending on their origin. The last stage forces every one into a single
standard form. `Normalizer`
([`normalize/pipeline.py`](../src/cybersec_slm/normalize/pipeline.py)) runs each
record through this:

- **Set aside synthetic sources.** Records from a source marked machine generated are
  counted by EDA but held out of the corpus, diverted to an audit sink rather than
  deleted.
- **Map and build** (`mappers.get_mapper`, then `build_record`): pick the mapper that
  knows this source's shape, map its fields onto the canonical ones, and fill in an
  id, a content hash, language and token counts, and labels.
- **Validate** against `CanonicalRecord`, a `pydantic` model that enforces the
  twenty two field schema. Anything that does not fit is written to a rejected pile,
  metadata only, no raw text, so a reject can never leak sensitive content into a
  log. A `FailureTracker` warns after five rejects from a source and hard pauses it
  after twenty.
- **Dedup once more.** A `NearDuplicateIndex` (again `datasketch` MinHash and LSH,
  with `numpy` for the math, exact only by policy) catches any remaining identical
  records and sends them to a duplicates pile.

Everything that passes is appended, one line at a time, to the finished file:
`data/final/dataset.jsonl`. Every record now has the exact same twenty two fields,
no matter which source it came from
([`normalize/schema.py`](../src/cybersec_slm/normalize/schema.py)):

```json
{
  "id": "b3f1c2a4-...-uuid4",
  "content_hash": "9f86d081...<64 hex>",
  "text": "User: Explain a reflected XSS attack. ...",
  "source": "AlicanKiraz0",
  "source_url": "https://huggingface.co/datasets/AlicanKiraz0/...",
  "license": "MIT",
  "origin_format": "jsonl",
  "lang": "en",
  "token_count": 512,
  "char_count": 2874,
  "pipeline_version": "0.1.0",
  "collected_at": "2026-07-12T18:23:07",
  "source_file": "Application Security/AlicanKiraz0/...jsonl",
  "record_type": "article",
  "domain_label": -1,
  "domain_name": "CYBERSEC",
  "subdomain_label": -1,
  "subdomain_name": "APPLICATION",
  "safe_unsafe": null,
  "confidence": null,
  "instruction": null,
  "reviewed_by": null
}
```

The design here is deliberate. The pipeline fills every field it can compute (the
id, the content hash, the counts, the timestamp, the topic names from its twelve
domain routing). The fields it does not own are stamped with explicit placeholders
rather than left out: the weak-supervision `domain_label` / `subdomain_label` are
`-1` (meaning "abstain, decide this later"), and the human-annotation fields
(`safe_unsafe`, `confidence`, `instruction`, `reviewed_by`) are `null`. That way the
schema is the same complete contract whether or not the downstream labeling has run,
and a mapper bug shows up as a rejected record instead of a silently missing field.

## The receipt

When the last record is written, `write_manifest`
([`normalize/manifest.py`](../src/cybersec_slm/normalize/manifest.py)) writes a
receipt next to the dataset, `data/final/manifest.json`. It records the record
count, the number of unique content hashes, the total token count, a SHA-256
fingerprint of the whole dataset file, the pipeline version and git commit that
produced it, and the breakdown by topic and license:

```json
{
  "dataset": "dataset.jsonl",
  "generated_at": "2026-07-12T19:40:11",
  "pipeline_version": "0.1.0",
  "git_commit": "b7f786f...",
  "record_count": 41230,
  "unique_content_hashes": 41230,
  "dataset_sha256": "e3b0c442...<64 hex>",
  "token_total": 18734512,
  "char_total": 102847331,
  "domains":  { "CYBERSEC": 41230 },
  "subdomains": { "CRYPTOGRAPHY": 9021, "THREAT_INTELLIGENCE": 6110, "...": 0 },
  "sources":  { "nvd-national-vulnerability-database": 3110, "...": 0 },
  "licenses": { "Apache-2.0": 12044, "MIT": 8901, "...": 0 }
}
```

This is what lets you trust the dataset later, and what lets you scope and roll back
a bad batch if one is ever found instead of discarding the whole thing. Because
`unique_content_hashes` and `dataset_sha256` are recorded, you can prove a release
is exactly what it claims to be.

And that is the whole trip. A name on a list becomes a licensed download, becomes a
flattened JSONL record, gets cleaned and masked and deduplicated, clears a quality
bar, is validated into a standard shape, and lands in the finished dataset with a
signed receipt attached.

## Under the hood: the libraries and how they work

This section goes one level deeper on each library, what it actually does here, and
which alternatives were considered and passed over.

### Format conversion: pandas, polars, pyarrow, json-repair

Every downloaded file passes through `to_jsonl`. The reader chooses by extension
against a priority list (`.parquet`, `.jsonl`, `.csv`, `.json`, `.xlsx`, ...), so a
source that ships the same data in several formats is read from the cleanest one.
Small and mid-size files load whole into a pandas DataFrame: `read_parquet` (through
pyarrow), `read_json(lines=True)` then plain `read_json`, and `read_csv` with an
encoding ladder that ends in `on_bad_lines="skip"` and latin-1 so a messy CSV still
yields rows. Malformed JSON is run through json-repair's `repair_json` first, which
fixes trailing commas, single quotes, and unquoted keys, so a slightly broken file
still parses instead of being lost. Files over a size threshold take a polars lazy
scan (`scan_csv` / `scan_parquet` / `scan_ndjson`): polars streams the file in
constant memory straight to JSONL, which is what lets a multi-gigabyte CSV convert
without blowing up RAM, and it falls back to the pandas path if it cannot handle a
file.

Why not the alternatives: loading everything in pandas alone runs out of memory on
the big tabular datasets, which is exactly why the polars lazy path exists for large
files. Dask or Spark would solve the memory problem but are heavyweight distributed
frameworks for what is a single-machine job. Hand-rolled `csv`/`json` stdlib parsing
cannot cope with the variety of real-world formats and encodings without becoming a
second pandas.

### PDFs: pymupdf

PDF sources are opened with pymupdf (the MuPDF binding) and read a page at a time,
each page becoming a record. pymupdf was chosen for speed and for the quality of its
text extraction. pdfplumber and pdfminer.six extract text too but are noticeably
slower on large documents; pypdf/PyPDF2 has weaker text extraction; Apache Tika is
accurate but drags in a Java runtime.

### Fetching datasets: huggingface-hub, kaggle, httpx, tenacity

For Hugging Face, `HfApi().dataset_info(ref, files_metadata=True)` lists every file
with its size; the fetcher keeps only the priority extensions, skips obvious
non-data files, and groups sharded files (`train-00000-of-00010`) by their base name
so all shards append into one JSONL instead of overwriting each other. Kaggle uses
the official client (`authenticate`, `dataset_list_files`, `dataset_download_file`),
unzipping archives before converting. Everything else, including the NVD REST feed
and PDFs, goes over httpx with `follow_redirects=True`, streamed to disk in 64 KB
chunks while a sha256 is computed so each raw file carries a fingerprint. tenacity
wraps the download in a declarative retry so a transient blip retries instead of
failing the source.

Why not the alternatives: the Hugging Face `datasets` library would load and
materialize a whole dataset through its own Arrow cache, which is heavier and more
opinionated than needed when the goal is just the raw files, so the lower-level
`huggingface-hub` file download is used instead. `requests` would work for the HTTP
fetches, but httpx gives first-class streaming and HTTP/2 and keeps the door open to
async; `urllib` is too low-level. Writing retry loops by hand is what tenacity
replaces.

### Crawling: scrapy, scrapy-playwright, selectolax

Website sources run through Scrapy, but in a separate subprocess (`crawl_runner`),
because Scrapy's Twisted reactor can only be started once per process and would clash
with the parent. Playwright drives a real Chromium browser for pages that only render
their content with JavaScript, and selectolax parses the returned HTML. The crawl is
bounded by a page cap and an allow-prefix so it stays on the target site and
terminates.

Why not the alternatives: requests plus BeautifulSoup cannot run JavaScript and gives
you no crawl orchestration, politeness, or retry handling. Selenium can drive a
browser but is heavier and flakier than Playwright. selectolax is used instead of
BeautifulSoup because it parses HTML several times faster, which matters across many
pages.

### PII redaction: presidio-analyzer, presidio-anonymizer, spaCy

`Redactor` runs Presidio's `AnalyzerEngine`, which combines the `en_core_web_lg`
spaCy model's named-entity recognition with Presidio's own pattern recognizers to
locate spans of personal data, then `AnonymizerEngine` replaces each span with a
typed placeholder such as `<EMAIL_ADDRESS>`. Because spaCy NER scans the whole text,
cost grows with length, so records over ~10,000 characters (env-tunable) skip
Presidio and take a linear regex fallback that still catches emails, US SSNs, IPv4,
credit cards (validated with the Luhn checksum so it will not redact every long
number), and phone numbers.

Why not the alternatives: pure regex misses names and anything context-dependent,
which is why it is kept only as the fast fallback, not the primary path. Cloud PII
services (AWS Comprehend, Google DLP) are accurate but cost money and, more
importantly, would send the corpus off the machine, which defeats the point of a
local, auditable pipeline. Running spaCy NER directly would find entities but not
give the recognizer-plus-anonymizer framework Presidio provides.

### Language identification: fastText lid.176

`LangFilter` loads fastText's `lid.176` model (a single compressed file that
identifies 176 languages) and calls `predict` on the first 2000 characters. It only
trusts a non-English verdict when the model's probability is at least 0.50; below
that the text is labelled "unknown" and kept, so obfuscated text like a phishing
email is not wrongly shipped off to translation. If fastText is unavailable it falls
back to langdetect, then to a stdlib heuristic (Unicode script ranges plus English
stopword frequency).

Why not the alternatives: langdetect is slower and less reliable on short strings, so
it is the fallback rather than the default. langid.py and Google's CLD3 are viable
but fastText's lid.176 is faster, ships as one model file, and is well benchmarked.

### Translation: deep-translator

When a record is confidently non-English and drop mode is off, `Translator` uses
deep-translator's `GoogleTranslator`, which calls Google's free endpoint with
automatic source detection and no local model. Long text is split into sub-5000
character chunks (on paragraphs, then lines), each record is capped at 8 chunks and a
20-second budget, and after 6 consecutive failures the online backend disables itself
for the rest of the run so a rate-limited endpoint cannot stall everything. An
offline argostranslate backend is used if installed.

Why not the alternatives: the paid Google Cloud Translation API is accurate but costs
per character and needs billing set up. Local neural models (MarianMT, NLLB) avoid the
network but pull in large per-language-pair weights and want a GPU to be quick.
argostranslate is fully offline but needs a language package installed per pair and is
lower quality, so it is the fallback. The free endpoint's weakness is exactly the
rate-limiting seen in practice, which is why the pipeline also offers dropping
non-English outright instead of translating.

### Deduplication: datasketch (MinHash + LSH)

Two layers. Exact dedup sha256-hashes the normalized text (lowercased, whitespace
collapsed); a repeat hash is an exact duplicate. Near-dup, when enabled, turns the
text into overlapping k-word shingles, hashes them into a MinHash signature of
`num_perm` permutations, and indexes the signature in datasketch's `MinHashLSH`, which
splits the signature into bands so only plausibly-similar records share a bucket; a
query returns candidates whose estimated Jaccard similarity clears the threshold. When
datasketch is not installed, a pure-python MinHash with banded LSH does the same with
deterministic coefficients. In this corpus, near-dup is deliberately turned off for
cross-source and final dedup (exact-only), because it was collapsing too many
similar-but-distinct security records (templated CVE text, MITRE techniques, log
lines). Only the exact-hash set is checkpointed, as JSON rather than pickle, so a
resumed run cannot be tricked into running attacker-controlled code by deserializing a
tampered checkpoint.

Why not the alternatives: comparing every pair is O(n squared) and impossible at
corpus scale, which is the whole reason for LSH. Embedding every record and doing
vector-similarity dedup would catch semantic duplicates but needs an embedding model
and a vector index and is far more expensive. Spark's MinHashLSH would distribute the
work but is overkill for an in-memory corpus this size. SimHash is a reasonable
alternative to MinHash but datasketch's MinHashLSH is the better-supported standard.

### Schema validation: pydantic v2

The final record is a pydantic v2 model, `CanonicalRecord`, configured with
`extra="forbid"` (an unexpected field is an error, so a mapper bug surfaces instead of
silently adding a column) and `str_strip_whitespace=True`. Field validators enforce
the contract: `text` at least 20 characters, `content_hash` a 64-character hex sha256,
`domain_name` and `subdomain_name` within their enums, `record_type` snapped to a
known set, integer labels at least -1, `safe_unsafe` limited to SAFE/UNSAFE/null. A
violation raises `ValidationError` and the record goes to the rejected sink.

Why not the alternatives: dataclasses plus hand-written checks would be verbose and
easy to let drift. jsonschema is declarative but less ergonomic and does no coercion.
marshmallow and attrs+cattrs are workable but pydantic v2's Rust core is fast and its
error messages point straight at the offending field.

### Metrics, and the small plumbing

The EDA metrics are pure standard library (`collections.Counter`,
`statistics.mean`/`median`) computed in one streaming pass, so the gate stays cheap
and predictable; pulling the whole corpus into pandas just to aggregate it would cost
memory for no real benefit. Around the edges: loguru provides the per-run
`pipeline.<pid>.log` and console format with far less boilerplate than stdlib logging;
python-dotenv loads `.env` (resolved from the working directory, then the package
root) so keys are present before any stage reads them; orjson serializes records on
the write path faster than stdlib json while staying correct; and ftfy repairs mojibake
(double-encoded UTF-8, stray replacement characters) during sanitize, which a plain
Unicode normalize would not catch.

## Where everything ends up

If you want to see any step for yourself, this is where each pile lives:

- `data/raw/` : everything downloaded, flattened to JSONL.
- `data/clean/` : the records that survived cleaning.
- `data/flagged/` : records set aside for a human to review.
- `data/dropped/` : everything removed, each with a reason.
- `data/final/dataset.jsonl` : the finished corpus.
- `data/final/manifest.json` : the receipt.
- `data/final/rejected.jsonl`, `duplicates.jsonl`, `excluded_synthetic.jsonl` : the
  final stage's audit sinks.
- `logs/` : the run log, the SQLite ingest ledger, and the EDA reports.

For the exact commands and flags, see [commands.md](commands.md). For the reasoning
behind the design, see [architecture/architecture.md](architecture/architecture.md).
