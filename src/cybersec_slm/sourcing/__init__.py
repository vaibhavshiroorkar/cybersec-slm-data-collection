#!/usr/bin/env python3
"""Search-engine source sourcing.

Finds *new* candidate cybersecurity sources by querying a search engine with
per-domain keyword sets, maps each hit into the finalized tracking sheet's row
schema, drops anything already present, and appends the survivors back to the
Google Sheet.

The pieces are deliberately small and independently testable:

    keywords.py   which keywords to search, per Sub-Domain (+ snippet vocab)
    search.py     Google Programmable Search client (query -> Result items)
    classify.py   URL/host -> (Category, Original Format); snippet -> Sub-Domain
    row.py        a Result -> a sheet row (the 16-column schema, in order)
    sheet.py      read existing rows for dedup + append new rows (Sheets API)
    run.py        orchestration + the entry the CLI calls

See ``sourcing/README.md`` for the column mapping and the credentials needed.
"""

from __future__ import annotations

from .run import discover

__all__ = ["discover"]
