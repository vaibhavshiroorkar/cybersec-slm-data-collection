#!/usr/bin/env python3
"""Schema normalization stage: cleaned records -> canonical dataset.jsonl.

Pipeline: Source Mapper -> Registry Dispatch -> build_record (id/hash/labels) ->
Pydantic Validation -> Near-Duplicate Check -> dataset.jsonl -> handoff.
"""

from .dedup import FailureTracker, NearDuplicateIndex
from .enrich import build_record, content_hash
from .manifest import build_manifest, write_manifest
from .mappers import (
    BaseMapper,
    ProseMapper,
    StructuredMapper,
    clean_text,
    get_mapper,
    register_mapper,
)
from .pipeline import Normalizer, run_normalization
from .schema import (
    ALLOWED_DOMAINS,
    SUBDOMAIN_NAMES,
    CanonicalRecord,
    normalize_domain,
    resolve_domain,
)

__all__ = [
    "run_normalization", "Normalizer",
    "CanonicalRecord", "normalize_domain", "resolve_domain", "ALLOWED_DOMAINS",
    "SUBDOMAIN_NAMES",
    "BaseMapper", "ProseMapper", "StructuredMapper", "register_mapper",
    "get_mapper", "clean_text",
    "build_record", "content_hash",
    "NearDuplicateIndex", "FailureTracker",
]
