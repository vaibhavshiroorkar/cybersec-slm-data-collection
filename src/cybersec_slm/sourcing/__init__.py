#!/usr/bin/env python3
"""Search-engine source discovery.

Finds *new* candidate cybersecurity sources by querying a self-hosted SearXNG
instance with per-domain keyword sets (round-robin across sub-domains), fetches
each hit's License (and host metadata) concurrently, drops anything already
present, and appends the survivors to the local catalog ``sources/Sources.csv``.

The pieces are deliberately small and independently testable:

    keywords.py       which keywords to search, per Sub-Domain (+ snippet vocab)
    search.py         SearXNG JSON client (query -> Result items)
    quality.py        drop obvious non-sources before enrichment
    classify.py       URL/host -> (Category, Original Format); snippet -> Sub-Domain
    row.py            a Result -> a catalog row (the schema, in order)
    enrich.py         fill License + host metadata for a discovered row
    license_detect.py deep per-source license detection (the priority field)
    sheet.py          read existing rows for dedup + append/delete catalog rows
    backfill.py       (re)detect licenses on existing rows, then blacklist reds
    blacklist.py      move confirmed-restrictive sources out of the catalog
    run.py            orchestration + the entry the CLI calls

See ``sourcing/README.md`` for the column mapping and the SearXNG setup.
"""

from __future__ import annotations

from .backfill import backfill_licenses
from .blacklist import move_flagged
from .license_detect import detect_license
from .run import discover

__all__ = ["discover", "detect_license", "backfill_licenses", "move_flagged"]
