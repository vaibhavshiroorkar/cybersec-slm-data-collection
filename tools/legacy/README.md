# Legacy tools — DO NOT use to grow a catalog

These are one-off, ad-hoc scripts that write `Sources.csv` / `Blacklist.csv`
**directly**, bypassing the sourcing engine and its gate (restricted-host,
license-integrity, liveness, dedup — see `src/cybersec_slm/sourcing/`).

They are the exact pattern that polluted the `ubi` catalog (e.g.
`add_rbi_and_union.py` added the `rbi.org.in` rows — a restricted host — with a
self-asserted `First-party` license, which is why ~44% of a prior catalog was
unverified guessed URLs). They are kept only for git history and reference.

**To grow a catalog, use the engine instead:**

```bash
cybersec-slm source                 # runs the one engine per the profile's sourcing.yaml
cybersec-slm source --backfill      # re-detect licenses on existing rows, blacklist reds
```

If you genuinely need a one-off manual row, use the dashboard's manual-add form or
`sourcing.row.build_manual_row` + `sourcing.sheet.append_rows`, which at least keep
the row in the catalog's schema — but prefer the engine so every row passes the gate.
