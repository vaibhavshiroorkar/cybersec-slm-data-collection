# Sourcing: search-engine source discovery

`cybersec-slm source` finds **new** candidate cybersecurity sources by querying
a self-hosted SearXNG instance with per-Sub-Domain keyword sets, maps each hit
into the catalog's row schema, fetches each hit's License and metadata, drops
anything already present, and appends the survivors to the local catalog
(`sources/Sources.csv`).

It's the inverse of [`ingestion/sources.py`](../ingestion/sources.py): that
module *reads* the catalog to drive ingestion; this one *grows* it.

## Engines (why runs used to come back empty)

SearXNG proxies many upstream engines. The general web engines (Google, Brave,
DuckDuckGo, Startpage, Wikipedia) are perpetually rate-limited or CAPTCHA-walled
for a self-hosted instance ("too many requests", "access denied"), so a query on
the `general` category returns nothing. Discovery therefore targets the reliable,
API-based engines that index licensable sources directly and are not throttled:

    github, openairedatasets, arxiv, semantic scholar     (datasets mode default)

GitHub is by far the highest commercial-valid yield (MIT/Apache/BSD repos); the
paper/dataset engines add reach. These engines ignore `site:` operators, so the
old host-scope clause and the dataset/text query qualifier are not applied.
Override the set with `--engines "a,b,c"` or `$SEARXNG_ENGINES`.

The SearXNG instance must expose the JSON API (`search: formats: [html, json]`
in its `settings.yml`). Point at it with `$SEARXNG_URL` (default
`http://localhost:8080`).

## Fill mode: balance the catalog to a per-domain target

`--target-per-domain N` runs a valid-gated fill: it reads each Sub-Domain's
existing **commercial-valid** count (rows the ingestion license gate passes),
computes the deficit to `N`, and tops up only the short domains. Each candidate is
enriched and kept only if its license is clearly commercial; a domain stops at `N`
or when its search is exhausted. `--max-total` caps the total valid rows added.

    cybersec-slm source --target-per-domain 83 --max-total 1000 --per-keyword 30

Because refined labeling can move a row to a neighbouring Sub-Domain, per-domain
totals may drift slightly from the searched target; re-running recomputes the
deficit from the live catalog and tops up whatever is still short, so repeated
runs converge on the target.

## GITHUB_TOKEN (effectively required at scale)

GitHub is the workhorse engine and its unauthenticated API allows only 60
requests/hour, far below what a large fill needs for license/metadata lookups.
Set `$GITHUB_TOKEN` to raise the limit; without it the run still works but
throttles hard and leans on the slower HTML license fallback.

## Backfill existing rows

`cybersec-slm source --backfill` deep-detects licenses for existing catalog rows
(blank/Unknown by default) and moves any confirmed-restrictive source to
`sources/Blacklist.csv`. See [`backfill.py`](backfill.py) and
[`blacklist.py`](blacklist.py).
