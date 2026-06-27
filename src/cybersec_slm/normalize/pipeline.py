#!/usr/bin/env python3
"""Schema-normalization orchestrator — walks the flowchart end to end.

    Raw cleaned record (clean_data/ or cleaned/)
        -> Source Mapper (prose / structured)  -> Registry Dispatch
        -> build_record (id, content_hash, lang/counts, labels, placeholders)
        -> Pydantic Validation ──invalid──> rejected.jsonl (metadata-only) ;
        |                                    FailureTracker (warn@5, hard-pause@20)
        -> Near-Duplicate Check (MinHash/LSH @ 0.65) ──seen──> duplicates.jsonl
        |   (every record's similarity score -> dedup_scores.jsonl)
        -> dataset.jsonl (append the full 22-field record)
        -> Update Hash List (seen + LSH)
        -> Handoff to annotation team

Outputs land under ``normalized/``: ``dataset.jsonl`` (the corpus), ``rejected.jsonl``
and ``duplicates.jsonl`` sinks, and ``dedup_scores.jsonl`` (near-dup audit). State
is rebuilt from an existing ``dataset.jsonl`` so the run is resumable.

Rejected records are written **metadata-only** by default (no raw text — avoids a
secondary PII leak in diagnostic logs); set ``CYBERSEC_SLM_DEBUG_REJECTS=1`` to
include the raw record while debugging.
"""

from __future__ import annotations

import argparse
import json
import os

from pydantic import ValidationError

from ..cleaning.common import find_input_files
from ..core import CLEAN_DATA, CLEANED, DATA_ROOT, LOGS, iter_jsonl, logger
from . import mappers
from .dedup import FailureTracker, NearDuplicateIndex
from .enrich import build_record
from .schema import CanonicalRecord

NORMALIZED = os.path.join(DATA_ROOT, "normalized")
DATASET = os.path.join(NORMALIZED, "dataset.jsonl")
REJECTED = os.path.join(NORMALIZED, "rejected.jsonl")
DUPLICATES = os.path.join(NORMALIZED, "duplicates.jsonl")
DEDUP_SCORES = os.path.join(NORMALIZED, "dedup_scores.jsonl")
REPORT = os.path.join(LOGS, "normalize_report.json")

DEBUG_REJECTS = os.environ.get("CYBERSEC_SLM_DEBUG_REJECTS", "").strip() in ("1", "true", "yes")

_COUNT_KEYS = ("in", "mapped", "skipped_no_text", "rejected", "exact_dups",
               "near_dups", "written")


def _short_reason(exc: Exception) -> str:
    """One-line reason from a Pydantic v2 error (or a plain ValueError)."""
    if isinstance(exc, ValidationError):
        try:
            e = exc.errors()[0]
            loc = ".".join(str(p) for p in e.get("loc", ()))
            return f"{loc}: {e.get('msg', 'invalid')}"
        except Exception:
            return "validation error"
    return str(exc) or "value error"


def _default_input() -> str:
    """Prefer clean_data/ (streaming path); fall back to cleaned/ (sequential path)."""
    if os.path.isdir(CLEAN_DATA) and any(os.scandir(CLEAN_DATA)):
        return CLEAN_DATA
    if os.path.isdir(CLEANED) and any(os.scandir(CLEANED)):
        return CLEANED
    return CLEAN_DATA


class _Sink:
    """Append-only JSONL sink (lazy open; one record/line)."""

    def __init__(self, path: str, append: bool):
        self.path = path
        self._fh = None
        self._mode = "a" if append else "w"

    def write(self, rec: dict) -> None:
        if self._fh is None:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            self._fh = open(self.path, self._mode, encoding="utf-8")
        self._fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None


class Normalizer:
    """Runs the normalization flowchart over cleaned records."""

    def __init__(self, *, resume: bool = True):
        self.index = NearDuplicateIndex()
        self.failures = FailureTracker()
        self.counts = {k: 0 for k in _COUNT_KEYS}
        self.resume = resume
        if resume:
            self.index.rebuild_from_jsonl(DATASET)
        self.dataset = _Sink(DATASET, append=resume)
        self.rejected = _Sink(REJECTED, append=resume)
        self.duplicates = _Sink(DUPLICATES, append=resume)
        self.scores = _Sink(DEDUP_SCORES, append=resume)

    # -- one record through the whole chain ---------------------------------
    def process(self, rec: dict, *, domain: str, source: str, log_id: str) -> None:
        self.counts["in"] += 1

        # paused source: its records go back to cleaning, skip until re-cleaned
        if source in self.failures.paused_sources():
            return

        # 1) Source Mapper + Registry Dispatch
        mapper = mappers.get_mapper(source, rec)
        mapped = mapper.map(rec, domain=domain, source=source)
        if mapped is None:                          # no usable text -> not a reject
            self.counts["skipped_no_text"] += 1
            return
        self.counts["mapped"] += 1

        # 2) build full record + Pydantic Validation (unknown domain -> ValueError)
        try:
            record = build_record(mapped)
            model = CanonicalRecord(**record)
        except (ValidationError, ValueError) as exc:
            reason = _short_reason(exc)
            category = self.failures.classify_failure(source, reason)
            self.counts["rejected"] += 1
            entry = {"id": log_id, "source": source, "domain": domain,
                     "mapper": type(mapper).__name__, "category": category,
                     "reason": reason}
            if DEBUG_REJECTS:
                entry["record"] = rec               # raw text gated behind debug flag
            self.rejected.write(entry)
            logger.debug(f"normalize: rejected {log_id} ({source}): {reason}")
            self.failures.should_pause(source)       # may flip the source to paused
            return

        # 3) Near-Duplicate Check (MinHash / LSH) + per-record score audit
        is_dup, dreason, score = self.index.is_duplicate(model.text)
        self.scores.write({"id": model.id, "source": source,
                           "score": round(score, 4),
                           "reason": dreason or "unique"})
        if is_dup:
            key = "exact_dups" if dreason == "exact" else "near_dups"
            self.counts[key] += 1
            self.duplicates.write({"id": model.id, "content_hash": model.content_hash,
                                   "reason": dreason, "score": round(score, 4),
                                   "source": source})
            return

        # 4) dataset.jsonl output  +  Update Hash List
        self.dataset.write(model.model_dump())
        self.index.add(model.text, model.id)
        self.counts["written"] += 1

    # -- drive over the cleaned corpus --------------------------------------
    def run(self, input_dir: str | None = None, limit: int | None = None) -> dict:
        input_dir = input_dir or _default_input()
        logger.info(f"normalize: input={input_dir} -> {DATASET}")
        n = 0
        try:
            for ap, sub_domain, source, _rel in find_input_files(input_dir):
                for i, rec in enumerate(iter_jsonl(ap)):
                    if limit is not None and i >= limit:
                        break
                    if rec.get("_parse_error"):
                        continue
                    log_id = f"{source}:{n:08d}"
                    self.process(rec, domain=sub_domain, source=source, log_id=log_id)
                    n += 1
        finally:
            self.dataset.close()
            self.rejected.close()
            self.duplicates.close()
            self.scores.close()
        return self._report()

    def _report(self) -> dict:
        report = {
            "counts": dict(self.counts),
            "kept_total": len(self.index),
            "paused_sources": sorted(self.failures.paused_sources()),
            "reject_reasons": dict(self.failures.reasons.most_common(20)),
            "reject_categories": dict(self.failures.categories),
            "unmapped_sources": mappers.unmapped_sources(),
            "outputs": {"dataset": DATASET, "rejected": REJECTED,
                        "duplicates": DUPLICATES, "dedup_scores": DEDUP_SCORES},
        }
        os.makedirs(os.path.dirname(REPORT) or ".", exist_ok=True)
        with open(REPORT, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        c = self.counts
        logger.info(
            "normalize done: in={in} written={written} "
            "skipped_no_text={skipped_no_text} rejected={rejected} "
            "exact_dups={exact_dups} near_dups={near_dups}".format(**c))
        logger.info(f"normalize: handoff-ready corpus -> {DATASET} "
                    f"({c['written']} records); report -> {REPORT}")
        return report


def run_normalization(input_dir: str | None = None, *, resume: bool = True,
                      limit: int | None = None, manifest: bool = True) -> dict:
    """Convenience entry point used by the CLI and other stages.

    Writes the provenance manifest alongside dataset.jsonl by default (every
    release ships its datasheet). Imported lazily to avoid a circular import.
    """
    report = Normalizer(resume=resume).run(input_dir, limit=limit)
    if manifest:
        from .manifest import write_manifest
        write_manifest()
    return report


def main():
    p = argparse.ArgumentParser(description="Schema-normalize cleaned records into dataset.jsonl")
    p.add_argument("--input", default=None,
                   help="cleaned-records root (default: clean_data/ then cleaned/)")
    p.add_argument("--fresh", action="store_true",
                   help="ignore any existing dataset.jsonl (do not resume/append)")
    p.add_argument("--limit", type=int, default=None, help="cap records per file (debug)")
    args = p.parse_args()
    run_normalization(args.input, resume=not args.fresh, limit=args.limit)


if __name__ == "__main__":
    main()
