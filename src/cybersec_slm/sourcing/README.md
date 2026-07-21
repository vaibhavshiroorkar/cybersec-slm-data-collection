# Sourcing: one engine, one config, real licenses

`cybersec-slm source` grows a profile's catalog (`sources/profiles/<profile>/Sources.csv`)
with **new** candidate sources. It is the inverse of
[`ingestion/sources.py`](../ingestion/sources.py): that module *reads* the catalog to
drive ingestion; this one *grows* it.

There is exactly **one** engine ([`orchestrator.py`](orchestrator.py)), driven by exactly
**one** config per profile ([`sourcing.yaml`](../../../sources/profiles/ubi/sourcing.yaml)).
This replaced three overlapping engines that used to write the same catalog (a legacy
SearXNG `discover`, a `harvest` bulk driver, and a `hybrid` coordinator) and the license
fabrication they carried.

## How a run works

    load sourcing.yaml (-> SourcingConfig; falls back to taxonomy defaults)
    pick the enabled backends in priority order
    round-robin across the profile's sub-domains (even coverage), and for each:
      pull the next (backend, keyword) shot, fetch a batch of Candidates
      pass every Candidate through the ONE gate (gates.py):
        1. host/shape   drop bad links, junk hosts, RESTRICTED hosts, listing pages
        2. off-topic    drop configured off-topic signal words
        3. dedup        drop URLs already in the catalog or seen this run
        4. liveness     HTTP-check non-API URLs; drop dead links
        5. license      license_verdict over the row's REAL license; drop blocked;
                        a first-party stamp is Unknown unless the profile opts in
      build the catalog row, overlay the backend's real metadata, append it
    stop on the global cap / per-sub-domain valid target / time budget / exhaustion
    write a review CSV + summary-*.json funnel the dashboard reads

Because *every* candidate from *every* backend goes through the same gate, a
licensing-restricted host can never be admitted on backend reputation — the
contradiction the old two-engine setup carried (the hybrid scorer trusted regulator
hosts the legal scope barred) is designed out.

## License integrity

The core rule: **no license is ever fabricated.** A row keeps only a license the
backend read from the source's real metadata (HuggingFace card, GitHub license API,
Zenodo/arXiv license field, CKAN package license) or an explicit `Unknown` that the
enrich step ([`enrich.py`](enrich.py)) may later fill from real metadata. The old
`pattern` backend that stamped `First-party (owner-authorized)` on guessed URLs is
gone. A self-asserted first-party stamp is admitted only when a profile sets
`license.allow_owned_first_party: true`.

## Backends

Real-metadata APIs first, SearXNG (no license metadata) as last resort:

    huggingface   github   arxiv   ckan   kaggle   zenodo   searxng

Each lives in [`backends/`](backends) and yields a `Candidate` carrying only real
metadata. Add one by implementing `Backend` and registering it in
[`backends/__init__.py`](backends/__init__.py). Enable/limit each in `sourcing.yaml`.

Credentials (all optional; a backend without its creds degrades to a no-op, never an
error): `GITHUB_TOKEN` (raises GitHub's rate limit), `KAGGLE_USERNAME`+`KAGGLE_KEY`,
`DATAGOVINDIA_API_KEY` (CKAN on data.gov.in), `ZENODO_TOKEN`. SearXNG needs a reachable
instance (`backends.searxng.url`, default `http://localhost:8080`) with the JSON API
enabled; it is last-resort and skipped gracefully when unreachable.

## Config: `sourcing.yaml`

One file per profile holds *only* sourcing settings — targets, country bias, license
policy, per-backend knobs, quality thresholds. The **taxonomy** (sub-domains, keywords,
enum codes, vocab, restricted hosts) stays in `keywords.yaml`, which every stage reads,
so the two never drift. A missing `sourcing.yaml` is fine: the engine derives sensible
defaults from the taxonomy. See [`config.py`](config.py) for the schema.

## Targets

`target.total` caps total new rows per run; `target.per_subdomain` tops each sub-domain
up to that many **commercial-valid** rows (seeded from the live catalog, so re-running
fills only the deficit and converges). `--max-total` / `--target-per-domain` /
`--max-minutes` on the CLI override for a one-off run.

## Backfill existing rows

`cybersec-slm source --backfill` deep-detects licenses for existing catalog rows
(blank/Unknown by default) and moves any confirmed-restrictive source to
`Blacklist.csv`. See [`backfill.py`](backfill.py) and [`blacklist.py`](blacklist.py).
