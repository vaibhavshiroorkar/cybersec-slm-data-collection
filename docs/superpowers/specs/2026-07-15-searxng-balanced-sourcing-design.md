# SearXNG balanced sourcing: engine targeting + valid-gated per-domain fill

Date: 2026-07-15
Status: approved (Approach 1)

## Problem

`cybersec-slm source` produces nothing. The SearXNG instance at `localhost:8080`
is up with the JSON API enabled, but the pipeline queries `categories=general`
and every general-category engine is currently suspended by its upstream
(brave/google "too many requests", duckduckgo "access denied", startpage
"CAPTCHA", wikipedia "too many requests"). So every query returns zero results
and no rows are ever appended.

The instance has 83 engines enabled. The API-based ones are not rate limited and
directly index licensable sources. A live probe confirmed usable yields:

- `github` -> ~30 repos/query, single page (page 2 is empty)
- `openairedatasets` -> ~3-10 dataset landing pages/query, single page
- `arxiv`, `semantic scholar`, `google scholar` -> ~10/page, paginate deeply
- `pubmed` -> ~20/query, single page

GitHub is the highest commercial-valid yield (MIT/Apache/BSD repos). The paper
engines return many hits but almost all resolve to "unknown" at the license gate,
so they contribute little to the commercial-only target.

Two other facts the design must respect:

- The paper engines paginate; GitHub and OpenAIRE do not. So the lever for more
  GitHub coverage is more distinct keywords, not deeper pages.
- `per_keyword=5` (the current default) truncates each query to 5 results, which
  throws away most of GitHub's 30.

## Goal

Make sourcing actually run against the working engines and fill the catalog to
about 1000 commercial-valid rows total, balanced toward about 83 per sub-domain,
keeping only sources the license gate (`ingestion.license_gate`) passes as
clearly commercial. Current state: 205 rows, 181 commercial-valid, heavily skewed
(Cryptography 83, most domains 4-13) across 12 sub-domains.

Success criteria:

- A run against the live instance returns results and appends commercial-valid
  rows (not zero).
- Given a per-domain valid target, each lagging sub-domain is topped up toward
  that target and stops at the target or when its search space is exhausted.
- The existing default `discover` behavior and its tests are unchanged.

## Non-goals and feasibility caveats

- Exactly 1000 or exactly 83/domain is not guaranteed. Niche sub-domains
  (Identity Access, GRC) may not have 83 findable commercial-valid sources; the
  run fills toward the target and stops at exhaustion. The honest deliverable is
  "as balanced as findable, capped at the target per domain".
- Reviving the general web engines (proxies, delays, self-hosted engine configs)
  is out of scope. The design routes around them.
- Text mode (tutorials/writeups) mostly comes from general web and stays weak;
  the focus is datasets mode.

## Design

### 1. Engine targeting (`search.py`)

`searxng_search` gains `engines: str | None = None`. When set, the comma-separated
engine list is passed to SearXNG as `engines=...` (SearXNG then uses those engines
regardless of category). When unset, behavior is unchanged (`categories=general`).

### 2. Engine sets and keyword breadth (`keywords.py`)

Add reliable engine sets and a resolver:

```
DATASET_ENGINES = ("github", "openairedatasets", "arxiv", "semantic scholar")
TEXT_ENGINES    = ("github", "stackoverflow", "arxiv", "semantic scholar")
def default_engines(is_datasets: bool) -> str  # comma-joined
```

Because GitHub is single-page, widen per-domain keyword coverage. Expand each
sub-domain's `DOMAIN_KEYWORDS` with GitHub-friendly terms (tool/topic names,
"labeled dataset", "detection", "benchmark", "awesome list", well-known dataset
names) so the single GitHub page per keyword covers more ground. Target roughly
15-20 keywords per sub-domain.

### 3. Drop the `site:` clause for API engines (`run.py`)

The API engines ignore `site:` operators, and a `(site:huggingface.co OR ...)`
clause actively corrupts a GitHub-engine query. When custom engines are in use
(the new default), the site clause is not appended. The `site_scope` parameter is
kept but has no effect once engines are set.

### 4. Valid-gated per-domain fill (`run.py`)

`discover` gains:

- `engines: str | None = None` (arg > env `SEARXNG_ENGINES` > `default_engines`
  per keyword set),
- `target_per_domain: int | None = None` (activates fill mode),
- `valid_only: bool = False` (drop non-commercial rows before append; implied
  True in fill mode).

When `target_per_domain` is None, the current loop runs unchanged (backward
compatible). When it is set, the run uses a valid-gated fill:

1. Read the catalog's existing commercial-valid count per sub-domain
   (`license_verdict(License) == "ok"`, grouped by Sub-Domain).
2. `need[d] = max(0, target_per_domain - existing_valid[d])`; skip domains whose
   need is 0.
3. Round-robin over the still-needy, non-exhausted domains. Each turn:
   - gather one keyword-query worth of deduped, quality-passing candidates for
     the domain (reusing the existing per-domain cursor / `_refill`, which pages
     deeper for the paginating engines),
   - enrich that batch concurrently on the existing thread pool (license first,
     then metadata),
   - keep the rows whose license passes the commercial gate, append them, and
     decrement `need[d]`,
   - deactivate the domain when `need[d] <= 0` or its search is exhausted.
4. Stop globally at `max_total` valid rows or when every domain is satisfied or
   exhausted. Also honors `max_minutes`.

Enriching per small batch (rather than fire-and-forget) puts license detection on
the critical path but keeps it concurrent, and it conserves the GitHub API budget
by only enriching what a domain still needs. Rows are appended per round so a long
run keeps its progress if interrupted.

The per-keyword result cap is floored in fill mode (`max(per_keyword, 20)`) so
GitHub's full page is captured rather than truncated to 5.

### 5. Per-domain valid-count helper (`sheet.py`)

Add `valid_counts_by_subdomain(csv_path)` returning `{sub-domain: n}` where n is
the number of existing rows whose License passes `license_verdict == "ok"`. Reused
by fill mode to compute each domain's deficit. Kept in `sheet.py` next to the
other catalog readers; imports the license gate.

### 6. CLI and dashboard

- `cli.py`: `--engines` and `--target-per-domain N` on the `source` subcommand;
  pass through to `discover`.
- `dashboard/control.py`: add `engines` and `target_per_domain` to the `source`
  entry in `_STAGE_FLAGS` and to `_FLAG_SPEC` so the dashboard can drive them.

### 7. Operational

GitHub is the workhorse and its unauthenticated API limit is 60/hour, far below
what an 800-row fill needs. `GITHUB_TOKEN` (already honored by `enrich.py` and
`license_detect.py`) becomes effectively required to reach the target; document it
in the sourcing README and surface it in run guidance. Without it the run still
works but throttles hard and leans on the slower HTML license fallback.

## Data flow (fill mode)

```
existing_valid = valid_counts_by_subdomain(csv)
need[d] = max(0, target - existing_valid[d]) for each selected domain
active  = [d for d in selected if need[d] > 0 and shots[d]]
while active and total_added < max_total and not expired:
    for d in active (round-robin):
        batch = gather_one_keyword(d)          # cursor/_refill; dedup; quality
        if batch empty and cursor[d] exhausted: deactivate d; continue
        enrich_concurrently(batch)             # license + metadata
        for row in batch:
            if license_verdict(row.License) == "ok":
                append(row); need[d] -= 1; total_added += 1
                if need[d] <= 0: deactivate d; break
    prune active (drop satisfied/exhausted)
```

## Testing

- `search.py`: `engines=` is forwarded to the request params; omitted when None.
- `keywords.py`: `default_engines` returns GitHub-first comma lists; every domain
  still has keywords and vocab (existing invariant test still passes).
- `run.py` fill mode (all with a fake `searxng_search` and a spy `Enricher`, no
  network):
  - fills a lagging domain to its target and stops there,
  - counts only commercial-valid rows toward the target (unknown-license
    candidates are gathered but not counted, and can be dropped),
  - reads existing valid counts so an already-full domain is skipped,
  - respects `max_total` and `max_minutes`,
  - does not scope custom-engine queries with a `site:` clause.
- Existing default-mode tests remain green (backward compatibility).

## Implementation steps

1. `search.py`: add and plumb `engines`.
2. `keywords.py`: engine sets + `default_engines`; expand `DOMAIN_KEYWORDS`.
3. `sheet.py`: `valid_counts_by_subdomain`.
4. `run.py`: engine resolution, drop site clause for API engines, fill mode.
5. `cli.py` and `dashboard/control.py`: new flags.
6. Tests, then a live end-to-end run against the instance.
