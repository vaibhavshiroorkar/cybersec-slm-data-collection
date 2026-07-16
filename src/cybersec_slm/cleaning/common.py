#!/usr/bin/env python3
"""Cleaning-stage config and helpers.

Shared concerns (logger, try_import, JSONL I/O, data paths) come from
``cybersec_slm.core``; this module adds the cleaning tunables, the input
walker, and small record helpers. Output path aliases (``OUT_*``) are kept so
the stage modules read naturally.
"""

from __future__ import annotations

import os

from ..core import (  # noqa: F401
    CLEAN_DATA,
    DROPPED,
    FLAGGED,
    LOGS,
    PARSE_ERROR,
    RAW_DATA,
    STAGES,
    JsonlWriter,
    iter_jsonl,
    json_dumps,
    logger,
    try_import,
)

# directory of this package (used by langfilter to look for a fasttext model)
PKG_DIR = os.path.dirname(os.path.abspath(__file__))

# output aliases (read naturally in the stage modules)
OUT_CLEAN_DATA = CLEAN_DATA       # cleaning output (sequential + per-source)
OUT_FLAGGED = FLAGGED
OUT_DROPPED = DROPPED
OUT_STAGES = STAGES
REPORTS = LOGS

# ------------------------------------------------------------- tunables ------
MIN_TEXT_CHARS = 50            # below this after sanitize -> structural drop
MAX_TEXT_CHARS = 100_000       # above this -> behavioral flag (extreme length)
GARBAGE_MAX = 0.30            # max fraction of non-text chars before flag
REPEAT_MAX = 0.50            # max fraction of repeated lines before flag
NEAR_DUP_THRESHOLD = 0.85     # Jaccard similarity for near-duplicates
SHINGLE_SIZE = 5              # word-shingle length for MinHash
MINHASH_PERM = 128            # MinHash permutations
LANGS = {"en"}                # languages to keep

# Date-ish field names sanitize will try to normalize to ISO-8601.
DATE_FIELDS = ("date", "collection_date", "last_updated", "published",
               "timestamp", "created", "modified")


# -------------------------------------------------------------- input walk ---
# Fetch scratch directories, never part of the corpus. ``fetch.fetch_url`` unzips
# an archive into ``<source>/_z``, combines the payload into a single top-level
# ``<source>.jsonl``, then removes it — a removal that fails silently on Windows
# (read-only entries / long paths) and has stranded millions of files. Anything
# left inside is a pre-combine intermediate whose records are already in the
# combined .jsonl, so descending in would both duplicate data and cost minutes.
SCRATCH_DIRS = frozenset({"_z"})


def find_input_files(input_dir: str = RAW_DATA):
    """Yield (abs_path, sub_domain, source, rel_path) for every input .jsonl.

    Layout (ingestion output): data/raw/<Sub-Domain>/<source>/<file>.jsonl
    Fetch scratch (:data:`SCRATCH_DIRS`) is pruned, not descended into.
    """
    if not os.path.isdir(input_dir):
        return
    for root, dirs, files in os.walk(input_dir):
        # In-place prune: os.walk reads `dirs` back, so this skips the subtree.
        dirs[:] = [d for d in dirs if d not in SCRATCH_DIRS]
        for fn in files:
            if not fn.lower().endswith(".jsonl"):
                continue
            ap = os.path.join(root, fn)
            rel = os.path.relpath(ap, input_dir).replace("\\", "/")
            parts = rel.split("/")
            sub_domain = parts[0] if parts else "unknown"
            source = parts[1] if len(parts) > 2 else (parts[0] if parts else "unknown")
            yield ap, sub_domain, source, rel


def text_of(rec: dict) -> str:
    """Best-effort text extraction; '' if absent/None."""
    for field in ("text", "content", "description", "body", "raw_log",
                  "message", "additional_info"):
        val = rec.get(field)
        if val and isinstance(val, str) and val.strip():
            return val.strip()
    # Fallback: join all non-empty string values
    parts = [str(v) for v in rec.values() if v and isinstance(v, str)]
    return " ".join(parts)
