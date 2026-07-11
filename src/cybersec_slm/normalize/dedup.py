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
import re
from collections import Counter
from pathlib import Path

import numpy as np
from datasketch import MinHash, MinHashLSH

from ..core import PARSE_ERROR, iter_jsonl, logger

# near-dup tuning (mirrors the diagram: threshold 0.65)
LSH_THRESHOLD = 0.65
MINHASH_PERM = 128
SHINGLE_SIZE = 5               # word-shingle length
ESCALATE_FAILURES = 5         # per-source rejects before a warning escalation
HARD_PAUSE_FAILURES = 20      # per-source rejects before a hard pause

_WORD = re.compile(r"\w+")


def _norm_tokens(text: str) -> list[str]:
    return _WORD.findall((text or "").lower())


class _Signature:
    """Per-text dedup artifacts, computed once: tokens -> fingerprint -> MinHash.

    ``is_duplicate`` + ``add`` both need the same tokenization, normalized sha256
    and (for non-exact hits) MinHash; the index memoizes the last text's signature
    so a check-then-commit on one record pays for each exactly once. The MinHash is
    lazy — an exact-fingerprint hit never builds it (matching the old early return).
    """

    __slots__ = ("text", "tokens", "fp", "_mh")

    def __init__(self, text: str):
        self.text = text
        self.tokens = _norm_tokens(text)
        self.fp = hashlib.sha256(" ".join(self.tokens).encode("utf-8")).hexdigest()
        self._mh: MinHash | None = None

    @property
    def minhash(self) -> MinHash:
        if self._mh is None:
            m = MinHash(num_perm=MINHASH_PERM)
            toks = self.tokens
            if len(toks) < SHINGLE_SIZE:
                shingles = {" ".join(toks)} if toks else set()
            else:
                shingles = {" ".join(toks[i:i + SHINGLE_SIZE])
                            for i in range(len(toks) - SHINGLE_SIZE + 1)}
            for sh in shingles:
                m.update(sh.encode("utf-8"))
            self._mh = m
        return self._mh


def _norm_fingerprint(text: str) -> str:
    """Normalized, time-independent sha256 used for exact-dup membership."""
    return _Signature(text).fp


def _minhash(text: str) -> MinHash:
    return _Signature(text).minhash


class NearDuplicateIndex:
    """Exact (normalized fingerprint) + near-dup (MinHash/LSH) membership.

    State is resumable from an existing ``dataset.jsonl`` (rebuild_from_jsonl).
    ``add`` commits a record to both indexes (the flowchart's "Update Hash List").
    """

    def __init__(self, threshold: float = LSH_THRESHOLD, *, near: bool = True):
        self.threshold = threshold
        self.near_enabled = near
        # Exact-only (near=False) skips the MinHash/LSH index: byte-identical
        # (normalized-fingerprint) duplicates are still removed, but fuzzy
        # near-duplicates are kept. Matches the clean-stage exact-only policy.
        self.lsh = MinHashLSH(threshold=threshold, num_perm=MINHASH_PERM) if near else None
        self.seen: set[str] = set()
        # key -> raw MinHash signature (np.ndarray), for the best-match score
        # audit. Raw hashvalues instead of MinHash objects: same math, a fraction
        # of the per-record memory (no per-instance permutation arrays).
        self._hashvalues: dict[str, np.ndarray] = {}
        self._last_sig: _Signature | None = None
        self._n = 0

    def _sig(self, text: str) -> _Signature:
        """Signature for `text`, memoized so check-then-add computes it once."""
        last = self._last_sig
        if last is not None and (last.text is text or last.text == text):
            return last
        sig = _Signature(text)
        self._last_sig = sig
        return sig

    def is_duplicate(self, text: str) -> tuple[bool, str, float]:
        """Return ``(is_dup, reason, score)`` without mutating state.

        ``score`` is the estimated Jaccard of the closest indexed record (1.0 for
        an exact-fingerprint hit, the best candidate's Jaccard for a near hit,
        0.0 when nothing is close enough to surface).
        """
        sig = self._sig(text)
        if sig.fp in self.seen:
            return True, "exact", 1.0
        if not self.near_enabled:              # exact-only: no fuzzy matching
            return False, "", 0.0
        m = sig.minhash
        candidates = self.lsh.query(m)
        if candidates:
            hv = m.hashvalues
            # Same estimator as MinHash.jaccard: fraction of matching perms.
            best = max((float(np.count_nonzero(hv == self._hashvalues[k])) / len(hv)
                        for k in candidates if k in self._hashvalues),
                       default=1.0)
            return True, "near", float(best)
        return False, "", 0.0

    def add(self, text: str, key: str) -> None:
        """Commit a kept record: register its fingerprint + LSH signature."""
        sig = self._sig(text)
        self.seen.add(sig.fp)
        self._n += 1
        if not self.near_enabled:              # exact-only: fingerprint set is enough
            return
        m = sig.minhash
        try:
            self.lsh.insert(key, m)
            self._hashvalues[key] = m.hashvalues
        except ValueError:
            pass                # duplicate LSH key (already inserted) — ignore

    def rebuild_from_jsonl(self, path: str | Path) -> int:
        """Repopulate state from an existing dataset.jsonl so runs are resumable."""
        p = Path(path)
        if not p.exists():
            return 0
        n = 0
        for rec in iter_jsonl(str(p)):
            if rec.get(PARSE_ERROR):
                continue
            text = rec.get("text") or ""
            sig = self._sig(text)
            if sig.fp in self.seen:
                continue
            key = rec.get("id") or rec.get("content_hash") or sig.fp
            self.add(text, key)                     # reuses sig via the memo
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
