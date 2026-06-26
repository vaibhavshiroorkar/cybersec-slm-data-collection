#!/usr/bin/env python3
"""Schema-normalization orchestrator — walks the flowchart end to end.

    Raw cleaned record (clean_data/)
        -> Source Mapper (prose / structured)
        -> Registry Dispatch
        -> Pydantic Validation ──invalid──> rejected.jsonl ; FailureTracker
        |                                   └─ fail rate high? -> hard pause (re-clean)
        -> Content Hash (sha256, content-only)
        -> Near-Duplicate Check (MinHash/LSH @ 0.65) ──seen──> duplicates.jsonl
        -> dataset.jsonl (append one record; stamped with a sequential
           `record_id` — rec_000000001, rec_000000002, … — plus its
           `content_hash`, the stable content fingerprint)
        -> Update Hash List (seen + LSH)
        -> Handoff to annotation team

Outputs land under ``normalized/``: ``dataset.jsonl`` (the corpus), plus the
``rejected.jsonl`` and ``duplicates.jsonl`` sinks. State is rebuilt from an
existing ``dataset.jsonl`` so the run is resumable.
"""

from __future__ import annotations

import argparse
import json
import os

from pydantic import ValidationError

from ..cleaning.common import find_input_files
from ..core import CLEAN_DATA, DATA_ROOT, LOGS, iter_jsonl, logger
from . import mappers
from .dedup import FailureTracker, NearDuplicateIndex, content_hash
from .schema import CanonicalRecord

NORMALIZED = os.path.join(DATA_ROOT, "normalized")
DATASET = os.path.join(NORMALIZED, "dataset.jsonl")
REJECTED = os.path.join(NORMALIZED, "rejected.jsonl")
DUPLICATES = os.path.join(NORMALIZED, "duplicates.jsonl")
REPORT = os.path.join(LOGS, "normalize_report.json")

_COUNT_KEYS = ("in", "mapped", "skipped_no_text", "rejected", "exact_dups",
               "near_dups", "written")


def _short_reason(exc: ValidationError) -> str:
    """One-line reason from a Pydantic v2 error (for the rejected sink)."""
    try:
        e = exc.errors()[0]
        loc = ".".join(str(p) for p in e.get("loc", ()))
        return f"{loc}: {e.get('msg', 'invalid')}"
    except Exception:
        return "validation error"


def _existing_records(path: str) -> int:
    """Count records already in `path` so a resumed run continues the rec_ sequence
    instead of restarting at 1 (which would collide with shipped ids)."""
    if not os.path.exists(path):
        return 0
    with open(path, "rb") as f:
        return sum(1 for _ in f)


class _Sink:
    """Append-only JSONL sink (lazy open; no trailing commas, one record/line)."""

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
        # sequential record_id counter; continues past existing records on resume
        self._seq = _existing_records(DATASET) if resume else 0
        self.dataset = _Sink(DATASET, append=resume)
        self.rejected = _Sink(REJECTED, append=resume)
        self.duplicates = _Sink(DUPLICATES, append=resume)

    # -- one record through the whole chain ---------------------------------
    def process(self, rec: dict, *, domain: str, source: str, log_id: str) -> None:
        self.counts["in"] += 1

        # paused source: its records go back to cleaning, skip until re-cleaned
        if source in self.failures.paused_sources():
            return

        # 1) Source Mapper + Registry Dispatch
        mapper = mappers.get_mapper(source, rec)
        canonical = mapper.map(rec, domain=domain, source=source)
        if canonical is None:                       # no usable text -> not a reject
            self.counts["skipped_no_text"] += 1
            return
        canonical["id"] = log_id
        self.counts["mapped"] += 1

        # 2) Pydantic Validation
        try:
            model = CanonicalRecord(**canonical)
        except ValidationError as exc:
            reason = _short_reason(exc)
            self.counts["rejected"] += 1
            self.rejected.write({"id": log_id, "source": source, "domain": domain,
                                 "reason": reason, "record": rec})
            logger.debug(f"normalize: rejected {log_id} ({source}): {reason}")
            self.failures.classify_failure(source, reason)
            self.failures.should_pause(source)      # may flip the source to paused
            return

        # 3) Content Hash Generation (content-only, time-independent)
        chash = content_hash(model.text)

        # 4) Near-Duplicate Check (MinHash / LSH)
        is_dup, dreason = self.index.is_duplicate(model.text, chash)
        if is_dup:
            key = "exact_dups" if dreason == "exact" else "near_dups"
            self.counts[key] += 1
            self.duplicates.write({"id": log_id, "content_hash": chash,
                                   "reason": dreason, "source": source})
            return

        # 5) dataset.jsonl output  +  6) Update Hash List
        out = model.model_dump()
        self._seq += 1
        out["record_id"] = f"rec_{self._seq:09d}"   # sequential handoff id (rec_000000001, …)
        out["content_hash"] = chash
        self.dataset.write(out)
        self.index.add(model.text, chash, log_id)
        self.counts["written"] += 1

    # -- drive over the cleaned corpus --------------------------------------
    def run(self, input_dir: str = CLEAN_DATA, limit: int | None = None) -> dict:
        logger.info(f"normalize: input={input_dir} -> {DATASET}")
        n = 0
        try:
            for ap, sub_domain, source, rel in find_input_files(input_dir):
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
        return self._report()

    def _report(self) -> dict:
        report = {
            "counts": dict(self.counts),
            "kept_total": len(self.index),
            "paused_sources": sorted(self.failures.paused_sources()),
            "reject_reasons": dict(self.failures.reasons.most_common(20)),
            "unmapped_sources": mappers.unmapped_sources(),
            "outputs": {"dataset": DATASET, "rejected": REJECTED,
                        "duplicates": DUPLICATES},
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


def run_normalization(input_dir: str = CLEAN_DATA, *, resume: bool = True,
                      limit: int | None = None) -> dict:
    """Convenience entry point used by the CLI and other stages."""
    return Normalizer(resume=resume).run(input_dir, limit=limit)


def main():
    p = argparse.ArgumentParser(description="Schema-normalize cleaned records into dataset.jsonl")
    p.add_argument("--input", default=CLEAN_DATA, help="cleaned-records root (default: clean_data/)")
    p.add_argument("--fresh", action="store_true",
                   help="ignore any existing dataset.jsonl (do not resume/append)")
    p.add_argument("--limit", type=int, default=None, help="cap records per file (debug)")
    args = p.parse_args()
    run_normalization(args.input, resume=not args.fresh, limit=args.limit)


if __name__ == "__main__":
    main()
