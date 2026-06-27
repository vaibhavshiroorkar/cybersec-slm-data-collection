#!/usr/bin/env python3
"""Schema normalization stage: cleaned records -> canonical dataset.jsonl.

Pipeline: Source Mapper -> Registry Dispatch -> Pydantic Validation ->
Content Hash -> Near-Duplicate Check -> dataset.jsonl -> handoff to annotation.
"""

from .dedup import FailureTracker, NearDuplicateIndex, content_hash
from .mappers import (
                      BaseMapper,
                      ProseMapper,
                      StructuredMapper,
                      clean_text,
                      get_mapper,
                      register_mapper,
)
from .pipeline import Normalizer, run_normalization
from .schema import ALLOWED_DOMAINS, CanonicalRecord, normalize_domain

__all__ = [
    "run_normalization", "Normalizer",
    "CanonicalRecord", "normalize_domain", "ALLOWED_DOMAINS",
    "BaseMapper", "ProseMapper", "StructuredMapper", "register_mapper",
    "get_mapper", "clean_text",
    "NearDuplicateIndex", "FailureTracker", "content_hash",
]
