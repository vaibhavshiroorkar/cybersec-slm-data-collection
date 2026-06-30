#!/usr/bin/env python3
"""Output schema for validated cleaned records.

Validates that every record coming out of data/clean/ meets the minimum contract
for cybersec SLM training. Run after the cleaning pipeline:

    from cybersec_slm.cleaning.schema import validate_corpus
    ok, bad = validate_corpus()
"""

from __future__ import annotations

import os

from ..core import CLEAN_DATA, iter_jsonl, logger

try:
    from pydantic import BaseModel, field_validator, model_validator

    class CybersecRecord(BaseModel):
        """Minimum schema every cleaned record must satisfy."""

        model_config = {"extra": "allow"}   # allow domain-specific extra fields

        source: str = ""
        url: str = ""
        license: str = ""
        text: str

        @field_validator("text")
        @classmethod
        def text_not_empty(cls, v: str) -> str:
            if not v or len(v.strip()) < 10:
                raise ValueError("text is empty or too short")
            return v

        @model_validator(mode="after")
        def warn_missing_provenance(self) -> CybersecRecord:
            if not self.source:
                logger.debug("record missing source field")
            if not self.url:
                logger.debug("record missing url field")
            return self

    _PYDANTIC = True

except ImportError:
    CybersecRecord = None       # type: ignore[assignment,misc]
    _PYDANTIC = False


def validate_corpus(cleaned_dir: str = CLEAN_DATA) -> tuple[int, int]:
    """Walk data/clean/ and validate every record against CybersecRecord.

    Returns (valid_count, invalid_count). Logs the first 20 validation errors
    so you can inspect them without drowning in output.

    If pydantic is not installed, skips validation and logs a warning.
    """
    if not _PYDANTIC:
        logger.warning("schema: pydantic not installed — skipping corpus validation")
        return 0, 0

    valid = invalid = 0
    shown = 0
    for root, _dirs, files in os.walk(cleaned_dir):
        for fn in files:
            if not fn.endswith(".jsonl"):
                continue
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, cleaned_dir).replace("\\", "/")
            for rec in iter_jsonl(path):
                try:
                    CybersecRecord.model_validate(rec)
                    valid += 1
                except Exception as exc:
                    invalid += 1
                    if shown < 20:
                        logger.warning(f"schema invalid [{rel}]: {exc}")
                        shown += 1

    total = valid + invalid
    pct = 100 * valid / total if total else 0
    logger.info(f"schema validation: {valid:,}/{total:,} valid ({pct:.1f}%), "
                f"{invalid:,} invalid")
    return valid, invalid
