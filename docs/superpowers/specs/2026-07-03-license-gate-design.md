# Ingestion license gate: commercial-only sources

**Status:** approved design · **Date:** 2026-07-03

## Context

`sources/Sources.csv` carries a free-text `License` column per source (SPDX id,
plain-English description, or nothing). Today that string is never validated: it
rides through ingestion → cleaning → normalization untouched and only surfaces at
the end, tallied in `data/final/manifest.json` for reporting. The only gate before
a source is fetched is `ingestion/allowlist.py`, which checks whether a source has
been *reviewed and approved* — it does not look at what the license actually says.

A scan of the current catalog's 140-ish rows shows real risk sitting behind that
gap: alongside clean cases (`MIT` ×30, `Apache-2.0` ×14, `CC0` variants, `Public
Domain (U.S. Government work, ...)`), there are GPL-3.0/LGPL-3.0 rows (copyleft),
`CC BY-NC-SA 4.0` (explicitly non-commercial + share-alike), 10 rows still marked
`to-verify`, 2 marked `Unknown`, and one row literally reading `"Need Permission
for commercial"`. Every one of these is currently fetchable.

We want an automated gate so only sources whose license clearly permits
unencumbered commercial use are ever fetched, closing that gap at ingestion time
rather than relying on the manual Green/Yellow/Red triage in
`docs/sources/source_acceptance_criteria.md` being applied consistently before a
source is marked `approved`.

Decisions locked during brainstorming:
- **Default-deny allowlist**, not a denylist — unrecognized license text fails
  closed, matching "only let commercial licenses pass" literally.
- **Enforced at ingestion**, alongside (not inside) the existing source allowlist —
  a separate concern, separately logged.
- **Copyleft/share-alike licenses (GPL, LGPL, CC-BY-SA) are treated as failing.**
  They technically permit commercial use but obligate releasing derivative work
  under the same terms, which conflicts with the intent here.
- **Unverified/unknown license text fails by default** — no separate "pending"
  status; it falls out naturally from default-deny (see Classification below).

## Architecture

A new, single-purpose module, following the existing pattern of one file per
concern under `cleaning/` (`dedup.py`, `pii.py`, `langfilter.py`):

```
src/cybersec_slm/ingestion/license_gate.py
    classify_license(raw: str) -> tuple[bool, str]   # (commercial_ok, reason)
```

Hooked into `worker.py::process_source`, as a second check immediately after the
existing `is_allowed()` call and before `_fetch_one`:

```python
allowed, reason = is_allowed(descriptor)
if not allowed:
    ... existing skip path (status="skipped", error=f"allowlist: {reason}") ...

ok, reason = license_gate.classify_license(descriptor.get("license"))
if not ok:
    result["status"] = "skipped"
    result["error"] = f"license: {reason}"
    logger.warning(f"  SKIPPED (license {reason}) {descriptor_key(descriptor)}")
    collector.record(..., status=f"skipped:license:{reason}")
    return result
```

Same shape as the existing allowlist skip, so `logs/completed_sources.txt`, the
ingest log, the clean report, and the dashboard's source table need **no**
changes — a license-skipped source is invisible to them exactly like an
allowlist-skipped one is today, distinguished only by the `license:` vs
`allowlist:` prefix in the skip reason for anyone reading logs.

`descriptor["license"]` (populated by `ingestion/sources.py` from the
`Sources.csv` `License` column) is the value checked — **not** the `license:`
field inside `sources/allowlist.yaml`. That YAML field is a point-in-time copy
written by `dump_allowlist_yaml()` when the file was generated and can go stale;
the CSV is what `worker.py` actually fetches with, so it is the source of truth.

**Kill switch:** `CYBERSEC_SLM_ENFORCE_LICENSE_GATE` env var, default on, mirroring
`CYBERSEC_SLM_ENFORCE_ALLOWLIST`'s existing convention — lets local dev/tests
disable it without a code change.

## Classification logic

Keyword-based over the lowercased, whitespace-collapsed license string (the free
text is too inconsistent — `"Apache 2.0"` vs `"Apache-2.0"`, `"CC by 4.0"` vs `"CC
BY-4.0"` — for exact matching). Checked in order; first match wins:

1. **Deny keywords** (checked first, so a compound string like `"CC BY-NC-SA
   4.0"` blocks even though it also contains an allow-keyword substring):
   `non-commercial`, `noncommercial`, `-nc` / ` nc ` (word-boundary, not a
   substring of e.g. "franc"), `-sa` / `share-alike` (word-boundary), `gpl`,
   `lgpl`, `copyleft`, `no license`, `all rights reserved`, `proprietary`,
   `need permission`.
2. **Allow keywords**, only if no deny keyword matched: `mit`, `apache`, `bsd`,
   `cc0`, `public domain`, `cc by 4.0` / `cc-by-4.0` (bare — the deny pass above
   already removed -nc/-sa variants), `us gov`, `u.s. government`,
   `cdla-permissive`, plus named-entity phrases already present in the catalog
   with documented permissive-with-attribution terms: `mitre att&ck`, `mitre
   capec`, `mitre cwe`, `ietf trust`.
3. **Default: deny**, reason `"unrecognized license: {raw!r}"`. Covers
   `to-verify`, `Unknown`, `Contact`, `EU Open`, `ATIS`, and anything not yet
   seen — until a human either fixes the `Sources.csv` license text to something
   unambiguous or (if genuinely a new permissive license) extends the allow
   list.

Empty/missing license string also denies (reason `"missing license"`) rather
than defaulting to `to-verify`-style leniency.

## Operational impact

Turning this on will start skipping currently-`approved` catalog rows whose
license fails classification — an estimated 15-20 of the ~140 rows (the
`to-verify`/`Unknown`/GPL/LGPL/NC/SA ones enumerated above). This is the intended
effect: those sources were never actually verified as commercial-safe, the gate
is just the first thing to say so out loud. `sources/Sources.csv` /
`sources/allowlist.yaml` content is **not** touched by this change — re-licensing
or removing those rows is a separate, manual follow-up.

## Testing

- `tests/ingestion/test_license_gate.py` — unit tests over `classify_license`
  using real strings pulled from `Sources.csv`: `MIT` / `Apache-2.0` /
  `CC0-1.0` / `Public Domain (U.S. Government work, ...)` / `MITRE ATT&CK Terms
  (free w/ attribution)` → pass; `GPL-3.0` / `LGPL 3.0` / `CC BY-SA 4.0` /
  `CC BY-NC-SA 4.0` / `to-verify` / `Unknown` / `""` / `"Need Permission for
  commercial"` → fail, each with a case asserting the returned reason string.
- One integration case added to the existing worker/parallel tests
  (`tests/ingestion/test_parallel_resume.py` or a new
  `tests/ingestion/test_worker.py`, whichever the implementer finds cleaner)
  confirming a descriptor with a non-commercial license comes back
  `status="skipped"`, `error` prefixed `"license:"`, and is never handed to
  `_fetch_one`.

## Non-goals (deliberate YAGNI)

Retroactively purging already-collected `data/` content fetched under a
now-blocked license; rewriting `Sources.csv` / `allowlist.yaml` license values;
SPDX-normalizing the license column; a UI/dashboard surface for license status
(the existing manifest license breakdown already reports what's in the corpus).

## Verification

`uv run pytest tests/ingestion/test_license_gate.py -q`; run
`uv run cybersec-slm run --limit 1` against a couple of known-bad rows (GPL,
to-verify) and confirm they log `SKIPPED (license ...)` and never appear in
`data/raw/`.
