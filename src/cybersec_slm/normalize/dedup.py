#!/usr/bin/env python3
"""Near-duplicate detection + failure tracking (flowchart bands 4 and the gate).

  * Near Duplicate Check — ``datasketch`` MinHash + MinHashLSH at Jaccard 0.65.
    The *exact* membership set uses a normalized fingerprint (``_norm_fingerprint``:
    lowercased, whitespace/token-collapsed sha256) so trivially-reformatted copies
    still collide. This is intentionally distinct from the record's schema
    ``content_hash`` (sha256 of the exact text) — the output field is the exact
    fingerprint; dedup matching is the normalized one.
  * Similarity scores — ``is_duplicate`` returns the estimated Jaccard of the best
    match so the pipeline can log per-record scores (anti-"dedup bypass via
    paraphrase": watch records that pass just under the threshold).
  * FailureTracker — per-source reject counts + categories (MAPPER_MISMATCH /
    DIRTY_DATA / AMBIGUOUS); warns at 5, hard-pauses a source at 20.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from datasketch import MinHash, MinHashLSH

from ..core import logger

# near-dup tuning (mirrors the diagram: threshold 0.65)
LSH_THRESHOLD = 0.65
MINHASH_PERM = 128
SHINGLE_SIZE = 5               # word-shingle length
ESCALATE_FAILURES = 5         # per-source rejects before a warning escalation
HARD_PAUSE_FAILURES = 20      # per-source rejects before a hard pause

_WORD = re.compile(r"\w+")


def _norm_tokens(text: str) -> list[str]:
    return _WORD.findall((text or "").lower())


def _norm_fingerprint(text: str) -> str:
    """Normalized, time-independent sha256 used for exact-dup membership."""
    return hashlib.sha256(" ".join(_norm_tokens(text)).encode("utf-8")).hexdigest()


def _minhash(text: str) -> MinHash:
    m = MinHash(num_perm=MINHASH_PERM)
    tokens = _norm_tokens(text)
    if len(tokens) < SHINGLE_SIZE:
        shingles = {" ".join(tokens)} if tokens else set()
    else:
        shingles = {" ".join(tokens[i:i + SHINGLE_SIZE])
                    for i in range(len(tokens) - SHINGLE_SIZE + 1)}
    for sh in shingles:
        m.update(sh.encode("utf-8"))
    return m


class NearDuplicateIndex:
    """Exact (normalized fingerprint) + near-dup (MinHash/LSH) membership.

    State is resumable from an existing ``dataset.jsonl`` (rebuild_from_jsonl).
    ``add`` commits a record to both indexes (the flowchart's "Update Hash List").
    """

    def __init__(self, threshold: float = LSH_THRESHOLD):
        self.threshold = threshold
        self.lsh = MinHashLSH(threshold=threshold, num_perm=MINHASH_PERM)
        self.seen: set[str] = set()
        self._minhashes: dict[str, MinHash] = {}   # key -> minhash, for score est.
        self._n = 0

    def is_duplicate(self, text: str) -> tuple[bool, str, float]:
        """Return ``(is_dup, reason, score)`` without mutating state.

        ``score`` is the estimated Jaccard of the closest indexed record (1.0 for
        an exact-fingerprint hit, the best candidate's Jaccard for a near hit,
        0.0 when nothing is close enough to surface).
        """
        if _norm_fingerprint(text) in self.seen:
            return True, "exact", 1.0
        m = _minhash(text)
        candidates = self.lsh.query(m)
        if candidates:
            best = max((m.jaccard(self._minhashes[k]) for k in candidates
                        if k in self._minhashes), default=1.0)
            return True, "near", float(best)
        return False, "", 0.0

    def add(self, text: str, key: str) -> None:
        """Commit a kept record: register its fingerprint + LSH signature."""
        self.seen.add(_norm_fingerprint(text))
        m = _minhash(text)
        try:
            self.lsh.insert(key, m)
            self._minhashes[key] = m
        except ValueError:
            pass                # duplicate LSH key (already inserted) — ignore
        self._n += 1

    def rebuild_from_jsonl(self, path: str | Path) -> int:
        """Repopulate state from an existing dataset.jsonl so runs are resumable."""
        p = Path(path)
        if not p.exists():
            return 0
        n = 0
        with p.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                text = rec.get("text") or ""
                key = rec.get("id") or rec.get("content_hash") or _norm_fingerprint(text)
                fp = _norm_fingerprint(text)
                if fp in self.seen:
                    continue
                self.add(text, key)
                n += 1
        logger.info(f"normalize: rebuilt dedup state from {p.name} ({n} records)")
        return n

    def __len__(self) -> int:
        return self._n


# Reject reason -> failure category (treated as a security indicator: a spike in
# MAPPER_MISMATCH often flags upstream schema drift or manipulation).
def categorize_failure(reason: str) -> str:
    r = (reason or "").lower()
    if "mapper" in r or "no usable text" in r:
        return "MAPPER_MISMATCH"
    if ("domain" in r or "text shorter" in r or "empty" in r or "content_hash" in r
            or "must not be" in r or "not in" in r):
        return "DIRTY_DATA"
    return "AMBIGUOUS"


class FailureTracker:
    """Per-source reject accounting with categories + escalation thresholds."""

    def __init__(self, escalate: int = ESCALATE_FAILURES,
                 threshold: int = HARD_PAUSE_FAILURES):
        self.escalate = escalate
        self.threshold = threshold
        self.failures: Counter[str] = Counter()
        self.reasons: Counter[str] = Counter()
        self.categories: Counter[str] = Counter()
        self._warned: set[str] = set()
        self._paused: set[str] = set()

    def classify_failure(self, source: str, reason: str) -> str:
        """Record a reject; warn once at the escalation threshold. Returns category."""
        category = categorize_failure(reason)
        self.failures[source] += 1
        self.reasons[reason] += 1
        self.categories[category] += 1
        if self.failures[source] == self.escalate and source not in self._warned:
            self._warned.add(source)
            logger.warning(f"normalize: ESCALATE — source '{source}' hit "
                           f"{self.escalate} rejects (latest category {category}); "
                           f"review before it reaches the hard pause")
        return category

    def should_pause(self, source: str) -> bool:
        """True exactly once, when ``source`` first crosses the hard-pause threshold."""
        if self.failures[source] >= self.threshold and source not in self._paused:
            self._paused.add(source)
            logger.error(f"normalize: HARD PAUSE — source '{source}' hit "
                         f"{self.failures[source]} rejects (>= {self.threshold}); "
                         f"send back to cleaning")
            return True
        return False

    def paused_sources(self) -> set[str]:
        return set(self._paused)
