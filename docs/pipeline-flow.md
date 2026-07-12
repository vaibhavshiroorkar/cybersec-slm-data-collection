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
is exactly what it claims to be. For repeatable releases, [`dvc.yaml`](../dvc.yaml)
wraps this same build so `dataset.jsonl` and `manifest.json` can be versioned to S3.

And that is the whole trip. A name on a list becomes a licensed download, becomes a
flattened JSONL record, gets cleaned and masked and deduplicated, clears a quality
bar, is validated into a standard shape, and lands in the finished dataset with a
signed receipt attached.

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
