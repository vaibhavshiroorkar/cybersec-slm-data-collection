# Plan: CKAN harvester to scale UBI sourcing to 10,000 catalog rows

## Goal

Run a sourcing pipeline that grows the UBI catalog (`sources/profiles/ubi/Sources.csv`)
to **10,000 catalog rows** — quality, Indian, finance-related, sub-domain-classified,
commercial-license-clean — and do it **fast**. The pipeline must be **generalized** so
any profile can use it via a customizable spec, but **optimized for UBI** now. Output
feeds the SLM pretraining corpus via the existing ingest → clean → normalize stages.

## Context (verified)

- UBI catalog today: **2130 rows**. Sub-domains: Compliance and Risk Management (633),
  Internal Audit (569), Corporate Governance (481), AML-KYC (447). Need ~**7,870 new
  rows** to reach 10,000.
- **1648 of 2130 (77%) are `data.gov.in`** rows at `https://www.data.gov.in/resource/<slug>`,
  all stamped `Government Open Data License - India (GODL)`. They already distribute
  across all 4 sub-domains (507/483/332/326) — so the existing
  `sourcing.classify.refine_domain` routes data.gov.in titles correctly. These 1648
  were **bulk-imported by hand**; there is no reproducible harvesting code for them.
- `data.gov.in` is a **CKAN** instance. Its catalog API (`/api/3/action/package_search`
  and friends) requires a registered **API key** (`DATA_GOV_IN_API_KEY`). The portal
  is currently in a maintenance window returning 404s; the resource URL shape and GODL
  licensing are stable and proven by the existing rows. The implementation agent must
  confirm the exact endpoint + auth header at build time once the portal is back.
- **License gate** already allows GODL: `license_gate._ALLOW` matches
  `godl|government open data license`. So harvested data.gov.in rows pass the
  ingestion gate **without any per-source enrichment fetch** — that is the speed win.
  The search-based `discover()` (run.py) does one enrichment HTTP call per candidate;
  a CKAN harvester reads license+metadata from the catalog response directly.
- Existing discovery (`sourcing.run.discover`) is SearXNG-keyword-based, slow
  (enrichment per source, GitHub 60/hr), and biased to github/arxiv/hf. It cannot
  realistically produce 7,870 new India-finance-commercial sources. CKAN bulk harvest
  is the only realistic volume engine.
- `Excluded.csv` (480 rows) and `Blacklist.csv` (517 rows) show manual curation
  already happened with reasons like "not related to India" — the Indian + finance +
  sub-domain filters are partly manual today.

## Decisions (resolved)

1. **Volume engine = CKAN harvester** for data.gov.in, generalized as a pluggable
   "harvest backend". SearXNG `discover()` stays as a secondary, optional fill for
   license-platform sources (HF/GitHub/Zenodo/Kaggle) the API can't cover — but the
   10k target is met by the CKAN harvester. (User chose: CKAN harvester.)
2. **10,000 = catalog rows total** (existing 2130 + ~7,870 net-new), not final
   dataset records. (User confirmed.)
3. **Filters expressed as a reusable harvest spec** per profile: host, CKAN query/fq
   facets (finance/banking terms), license stamp (GODL), country (India), field
   (Finance), per-sub-domain target. The spec lives in a new
   `sources/profiles/<name>/harvest.yaml`, editable like `keywords.yaml`.
4. **Quality for pretraining**: data.gov.in datasets are frequently pure tabular /
   numeric with little prose. The harvester applies a **quality pre-filter** before
   appending (reject empty titles, reject obvious non-text-only resources where the
   description+title have no finance keyword hit, dedup by resource id). A separate
   *ingestion-side* text-volume gate already exists (`clean` min-text-chars); the
   harvester does not duplicate that, it only filters at the catalog row level.
5. **No new license-gate relaxation.** GODL is already allowed; nothing changes in
   `license_gate.py`. `restricted_hosts` (rbi.org.in etc.) stays — the harvester
   targets data.gov.in, which is not restricted.

## Design

### A. Pluggable harvest backends

New module `src/cybersec_slm/sourcing/harvest/`:

- `__init__.py` — registry of backends by name.
- `base.py` — `HarvestBackend` protocol: `harvest(spec: HarvestSpec) -> Iterator[dict]`
  yielding catalog-row dicts (same `CATALOG_COLUMNS` shape as `row.build_manual_row`).
- `ckan.py` — the CKAN backend. Paginates `package_search` with `rows`/`start`, applies
  `fq` facet filters from the spec, maps each CKAN `package`/`resource` to a catalog
  row (Name, Sub-Domain via `classify.refine_domain`, Description, Dataset Link =
  `https://www.data.gov.in/resource/<slug>`, Category=`Dataset`, Original Format from
  resource `format`, License=`Government Open Data License - India (GODL)`,
  Country=`India`, Field=`Finance`, Date Added, Verified?=`Yes`). Reads API key from
  `DATA_GOV_IN_API_KEY` env; raises a clear actionable error if unset. Retries with
  backoff; respects CKAN `rate_limit` if the response carries one.

The registry lets a future profile add a non-CKAN backend (e.g. a direct OpenAlex or
Zenodo harvester) without touching the driver.

### B. Harvest spec (`harvest.yaml`)

New per-profile file `sources/profiles/<name>/harvest.yaml`. For UBI:

```yaml
target_total: 10000
backends:
  - name: ckan
    base_url: https://www.data.gov.in
    api_key_env: DATA_GOV_IN_API_KEY
    action: package_search
    # CKAN filter query facets — finance/banking/AML/audit/governance topics
    fq_groups:
      - field: groups        # CKAN 'sector' groups
        values: [banking, finance, economy]
    # Free-text query terms broadened per sub-domain
    per_domain_queries:
      "Compliance and Risk Management": [banking, "credit risk", "capital adequacy",
                                         "non performing assets", "regulatory reporting"]
      "AML-KYC": [fraud, "money laundering", "suspicious transactions", "financial fraud"]
      "Internal Audit": [audit, "internal audit", "audit findings", "control deficiency"]
      "Corporate Governance": ["corporate governance", "board of directors", "annual report",
                               "shareholding", "companies act"]
    rows_per_page: 100
    max_results: 12000           # over-fetch to survive dedup + quality drops
    license: "Government Open Data License - India (GODL)"
    country: India
    field: Finance
    quality:
      require_title_min_chars: 8
      require_any_keyword: true   # title+desc must hit a per-domain keyword
    dedup_by: resource_id
```

Defaults seeded from the taxonomy so a fresh profile works with no file (mirror the
`keywords.yaml` pattern in `sourcing.profiles.ensure`).

### C. Harvest driver (`sourcing/harvest/run.py`)

`run_harvest(profile=None, *, dry_run=False, target_total=None, client=None) -> dict`:

1. Load `harvest.yaml` (or taxonomy default).
2. Read existing catalog links via `sheet.existing_links` (dedup by normalized URL;
   CKAN `resource_id` is a secondary dedup key the spec can request).
3. Compute per-sub-domain deficits toward `target_total` (reuse
   `sheet.valid_counts_by_subdomain` so the deficit counts only gate-passing rows —
   though for UBI ~all rows are GODL/valid, so this is ~= total).
4. For each backend, round-robin per-domain queries, paginate, map each package to a
   row, apply the quality pre-filter, dedup against existing + this-run seen set, and
   buffer survivors.
5. Append survivors in batches via `sheet.append_rows` (atomic, header-safe — reuse
   the exact I/O `discover()` uses). Stream progress via `logger.info("harvest: ...")`
   with the `source:` marker the dashboard watches, plus a `summary-*.json` with a
   funnel (`found`, `quality_dropped`, `duplicates`, `appended`, `by_domain`).
6. Stop when `target_total` reached or every backend's queries exhausted.

This mirrors `discover()`'s fill-loop shape (round-robin, deficit, batch append,
funnel) so the dashboard and tests generalize, but replaces SearXNG+enrichment with a
single paginated API read — orders of magnitude faster.

### D. CLI

Add `cybersec-slm source --harvest [--dry-run] [--target N]` to the existing `source`
subparser in `cli.py`. `--harvest` switches the subcommand from SearXNG discovery to
the harvest driver. `--target` overrides `target_total` in the spec. Keep `--dry-run`
parity. Document in `docs/commands.md` under `source`.

### E. Profile integration

- `Taxonomy` gains an optional `harvest_spec: dict | None` (default `None`) holding the
  in-code default, seeded to `harvest.yaml` on `profiles.ensure` (mirror
  `keywords.yaml`). For UBI, populate it with the spec above; for cybersec leave it
  `None` (cybersec is search-discovery-first; harvesting is opt-in).
- `profiles.ensure` writes `harvest.yaml` only when absent (never overwrites edits).

### F. Quality pre-filter (catalog-row level)

In `ckan.py` mapping, before yielding a row:
- Drop if CKAN `title` < `require_title_min_chars` or empty.
- If `require_any_keyword`, drop unless `title + notes/description` hits at least one
  of the per-domain query terms (prevents off-topic resources like the COVID daily-rate
  rows that crept into the existing 1648 — see the repeated `covid-19-district-wise-
  positivity-rate` URLs).
- This is a recall/precision trade dial; defaults are conservative (keep most), since
  the ingestion + clean stages already drop no-text records.

### G. Sub-domain classification

Reuse `sourcing.classify.refine_domain(title, snippet, domain_vocab)` with the active
profile's vocab — already proven on the 1648 existing rows. If `refine_domain` returns
the taxonomy default, keep it; the round-robin queries are already per-sub-domain so
the default is the queried domain.

## Tasks (ordered)

1. **`sourcing/harvest/base.py`** — `HarvestSpec` dataclass + `HarvestBackend`
   protocol + registry.
2. **`sourcing/harvest/ckan.py`** — CKAN `package_search` client: paginate, map
   package→row, quality pre-filter, API-key env + clear error, retries/backoff.
   Confirm the exact endpoint + auth header against the live portal (it is in a
   maintenance window now — verify before relying on a path).
3. **`sourcing/harvest/run.py`** — `run_harvest`: load spec, dedup vs catalog,
   per-domain deficit, round-robin paginate, batch `append_rows`, funnel summary to
   `logs/discovered/harvest-<date>.json`.
4. **`harvest.yaml` support** — read in `sourcing/catalog.py` or a new
   `sourcing/harvest/spec.py`; seed default from `Taxonomy.harvest_spec` in
   `profiles.ensure` (write-only-if-absent).
5. **UBI spec** — add `harvest_spec` to `ubi.py` `TAXONOMY` with the finance/banking
   `fq_groups` + per-domain queries above; write `sources/profiles/ubi/harvest.yaml`
   on `ensure`.
6. **CLI** — `cybersec-slm source --harvest [--dry-run] [--target N]` in `cli.py`;
   update `docs/commands.md`.
7. **`.env.example`** — add `DATA_GOV_IN_API_KEY` (optional, required for the CKAN
   backend) with a one-line note; document in `docs/commands.md` config table.
8. **Tests** — `tests/test_harvest_ckan.py` with a mocked CKAN `package_search`
   payload (fixture JSON), asserting: row mapping, quality filter, dedup vs an
   existing-catalog fixture, idempotency (second run appends 0), per-domain deficit
   respects `target_total`, dry-run writes nothing. Add `tests/test_harvest_spec.py`
   for `harvest.yaml` load + taxonomy default seeding.
9. **Validation** —
   - `uv run pytest`
   - `uv run cybersec-slm source --harvest --dry-run --target 10000` → confirm the
     funnel (found/quality_dropped/duplicates/appended projections) without writing.
   - With `DATA_GOV_IN_API_KEY` set: `uv run cybersec-slm source --harvest --target 10000`
     → confirm catalog grows toward 10,000; re-run → idempotent (0 appended).
   - Spot-check: `Import-Csv sources/profiles/ubi/Sources.csv | Measure` and per-sub-
     domain counts; confirm all new rows are GODL + India + Finance and pass
     `license_verdict == "ok"`.
   - Run ingest on a sample of new rows to confirm the existing `kind` dispatch
     handles `data.gov.in/resource/<slug>` (HTML landing page → likely `website` kind;
     if the resource exposes a CSV/data API URL, the row's `Original Format` guides
     dispatch). Fix dispatch only if a gap surfaces.

## Risks / edge cases

- **Portal maintenance / endpoint drift**: data.gov.in is mid-maintenance now. The
  implementation agent must confirm the live CKAN action path and auth header before
  building `ckan.py`; the 404s seen during planning are maintenance, not a wrong path.
  If `package_search` is truly not exposed, fall back to the documented per-resource
  data API list (`/apis`) keyed by `DATA_GOV_IN_API_KEY` — the spec's `action` field
  is configurable for exactly this.
- **Pretraining text quality**: most data.gov.in resources are tabular. The harvester
  gets *sources* into the catalog; whether each yields useful pretraining *text* is the
  ingestion+clean stage's job (PDF reports and text-CSV descriptions do; pure-numeric
  tables mostly get dropped at clean's min-text gate). The harvester's quality
  pre-filter biases toward titled/described/finance-keyworded resources but does not
  guarantee prose. Recommend a follow-up to ingest a sample and measure clean yield
  before committing to all 10k.
- **Off-topic leakage**: the existing 1648 include non-finance rows (COVID positivity,
  UPSC recruitment). The `require_any_keyword` + per-domain query scope is the fix;
  expect to re-run after tuning keywords.
- **Rate limiting**: CKAN APIs often cap unauthenticated or even keyed calls. Use
  `rows_per_page=100`, modest backoff, and a `max_results` over-fetch budget. If a
  key is unavailable, fail fast with an actionable message rather than churning.
- **Dispatch for `data.gov.in/resource/<slug>`**: the ingestion `kind` mapper may route
  these to `website` (HTML landing page) rather than the underlying data file. Confirm
  in task 9; if the landing page crawl yields no records, the row may need the actual
  resource download URL — extend `ckan.py` to store the resource's direct data URL in
  `Dataset Link` (or a `Note`) so ingestion fetches data, not the landing page.

## Out of scope

- Cybersec profile harvesting (search-discovery-first there; harvesting is opt-in).
- Relaxing the license gate or restricted_hosts.
- New ingestion fetchers (reuse existing `kind` dispatch; only extend if task 9 finds
  a gap).
- Final-dataset record counting (the 10k target is catalog rows; record volume is the
  clean/EDA stage's concern).
- A UI for editing `harvest.yaml` (it is a plain editable YAML, like `keywords.yaml`).
