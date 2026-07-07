#!/usr/bin/env python3
"""Synthetic-source filter (flowchart: gate before the Source Mapper).

A source flagged ``Is Synthetic? = Yes`` in ``sources/Sources.csv`` is
model-generated, fabricated, or simulated data. It is still fetched, cleaned, and
counted by the EDA sufficiency gate, but its records must not enter the final
training corpus (``data/final/dataset.jsonl``). This module decides, per cleaned
record, whether it belongs to such a source.

The decision is a curated-flag lookup, not content analysis: a human marks the
*source* in the catalog; here we match each record's ``url`` back to a flagged
catalog row via :func:`cybersec_slm.ingestion.sources.source_identity` (the same
``/datasets/<org>/<name>`` identity the allowlist keys on). Matching on the URL
ref — not the folder slug — is what keeps distinct datasets that share a slug
(e.g. the many ``darkknight25`` sources) cleanly separated.

Public API:
    SyntheticFilter().is_synthetic(rec) -> bool
"""

from __future__ import annotations

from ..ingestion.sources import source_identity, synthetic_identities


class SyntheticFilter:
    """Membership test for records belonging to a synthetic-flagged source."""

    def __init__(self, spec: str | None = None):
        # Loaded once; the catalog CSV is the single source of truth for the flag.
        self._ids = synthetic_identities(spec)

    def is_synthetic(self, rec: dict) -> bool:
        """True if ``rec`` comes from a source flagged synthetic in the catalog."""
        if not self._ids:
            return False
        ident = source_identity(rec.get("url") or rec.get("source_url"))
        return ident is not None and ident in self._ids

    def __len__(self) -> int:
        return len(self._ids)
