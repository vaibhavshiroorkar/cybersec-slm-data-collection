#!/usr/bin/env python3
"""Source discovery: grow a profile's ``Sources.csv`` from real, licensed sources.

One engine, one config per profile. The engine round-robins across a profile's
sub-domains, fetching candidates from pluggable backends (HuggingFace, GitHub,
arXiv, CKAN, Kaggle, Zenodo, and SearXNG as last resort), passes every candidate
through one gate (restricted-host / license-integrity / liveness / dedup), and
appends the survivors. Every kept row carries a *real* license from the source's
metadata or an explicit Unknown — never a fabricated one.

The pieces are deliberately small and independently testable:

    config.py         one per-profile ``sourcing.yaml`` -> SourcingConfig
    backends/         pluggable source fetchers -> Candidate (real license only)
    gates.py          the single accept/reject gate every candidate passes
    dedup.py          against-catalog + within-run URL dedup
    orchestrator.py   the engine: plan -> fetch -> gate -> enrich -> append
    keywords.py       taxonomy view: keywords/vocab/restricted hosts per Sub-Domain
    search.py         SearXNG JSON client (query -> Result items)
    quality.py        drop obvious non-sources (junk/restricted/listing hosts)
    classify.py       URL/host -> (Category, Original Format); snippet -> Sub-Domain
    row.py            a Result -> a catalog row (the schema, in order)
    enrich.py         fill License + host metadata for a discovered row
    license_detect.py deep per-source license detection (the priority field)
    sheet.py          read existing rows for dedup + append/delete catalog rows
    backfill.py       (re)detect licenses on existing rows, then blacklist reds
    blacklist.py      move confirmed-restrictive sources out of the catalog
    run.py            thin re-export of the engine's entry point

See ``sourcing/README.md`` for the column mapping and backend setup.
"""

from __future__ import annotations

from .backfill import backfill_licenses
from .blacklist import move_flagged
from .license_detect import detect_license
from .run import source

__all__ = ["source", "detect_license", "backfill_licenses", "move_flagged"]
