#!/usr/bin/env python3
"""Deduplication — exact + near-duplicate.

Exact: sha256 of normalized text (lowercased, whitespace-collapsed).
Near:  MinHash + LSH. Uses `datasketch` when installed; otherwise a compact
       pure-python MinHash with banded LSH (same idea, no dependency).

The Deduper holds an in-memory index for the whole run (dedup is global across
the corpus). Fine at this corpus size; see README for scaling notes.

Public API:
    d = Deduper()                  # backend auto-selected
    is_dup, reason = d.add(text)   # returns ("" reason when unique)
"""

from __future__ import annotations

import hashlib
import os
import pickle
import re

from .common import MINHASH_PERM, NEAR_DUP_THRESHOLD, SHINGLE_SIZE, logger, try_import

_WS_RE = re.compile(r"\s+")
_MERSENNE = (1 << 61) - 1          # large prime for hash mixing
_MAXHASH = (1 << 32) - 1


def normalize_for_hash(text: str) -> str:
    return _WS_RE.sub(" ", text.lower()).strip()


def _shingles(text: str, k: int) -> set[str]:
    words = text.split()
    if len(words) < k:
        return {" ".join(words)} if words else set()
    return {" ".join(words[i:i + k]) for i in range(len(words) - k + 1)}


def _exact_hash(text: str) -> str:
    return hashlib.sha256(normalize_for_hash(text).encode("utf-8")).hexdigest()


class _FallbackLSH:
    """Minimal MinHash + banded LSH (no third-party deps)."""

    def __init__(self, num_perm=MINHASH_PERM, threshold=NEAR_DUP_THRESHOLD):
        self.num_perm = num_perm
        # choose bands so that ~ (1/bands)^(1/rows) ≈ threshold; simple split.
        self.bands = 16 if num_perm % 16 == 0 else 8
        self.rows = num_perm // self.bands
        # random-ish but deterministic (a, b) coefficients for permutations.
        import random
        rnd = random.Random(42)
        self._ab = [(rnd.randint(1, _MERSENNE - 1), rnd.randint(0, _MERSENNE - 1))
                    for _ in range(num_perm)]
        self._buckets: list[dict] = [dict() for _ in range(self.bands)]
        self._sigs: list[tuple[int, ...]] = []

    def _signature(self, shingles: set[str]) -> tuple[int, ...]:
        hs = [int.from_bytes(hashlib.blake2b(s.encode("utf-8"), digest_size=8).digest(),
                             "big") for s in shingles]
        sig = []
        for a, b in self._ab:
            sig.append(min(((a * h + b) % _MERSENNE) & _MAXHASH for h in hs) if hs else 0)
        return tuple(sig)

    @staticmethod
    def _similarity(s1, s2) -> float:
        return sum(1 for x, y in zip(s1, s2, strict=False) if x == y) / len(s1)

    def add(self, text: str) -> tuple[bool, str]:
        sh = _shingles(text, SHINGLE_SIZE)
        if not sh:
            return False, ""
        sig = self._signature(sh)
        band_keys = []
        for bi in range(self.bands):
            band = sig[bi * self.rows:(bi + 1) * self.rows]
            band_keys.append((bi, hash(band)))
        # check candidates sharing any band bucket
        seen_ids = set()
        for bi, key in band_keys:
            seen_ids.update(self._buckets[bi].get(key, ()))
        for idx in seen_ids:
            if self._similarity(sig, self._sigs[idx]) >= NEAR_DUP_THRESHOLD:
                return True, "near-duplicate (minhash)"
        # not a dup -> index it
        new_id = len(self._sigs)
        self._sigs.append(sig)
        for bi, key in band_keys:
            self._buckets[bi].setdefault(key, []).append(new_id)
        return False, ""


class _DatasketchLSH:
    """Near-dup index backed by datasketch MinHashLSH."""

    def __init__(self, datasketch, num_perm=MINHASH_PERM, threshold=NEAR_DUP_THRESHOLD):
        self._ds = datasketch
        self.num_perm = num_perm
        self.lsh = datasketch.MinHashLSH(threshold=threshold, num_perm=num_perm)
        self._n = 0

    def _minhash(self, text: str):
        mh = self._ds.MinHash(num_perm=self.num_perm)
        for sh in _shingles(text, SHINGLE_SIZE):
            mh.update(sh.encode("utf-8"))
        return mh

    def add(self, text: str) -> tuple[bool, str]:
        sh = _shingles(text, SHINGLE_SIZE)
        if not sh:
            return False, ""
        mh = self._minhash(text)
        if self.lsh.query(mh):
            return True, "near-duplicate (minhash)"
        self.lsh.insert(f"d{self._n}", mh)
        self._n += 1
        return False, ""


class Deduper:
    """Exact + near-duplicate detector with auto backend selection."""

    def __init__(self, use_datasketch="auto", enabled: bool = True):
        self.enabled = enabled
        self._seen_exact: set[str] = set()
        if not enabled:
            self._near = None
            self.backend = "disabled"
            return
        ds = try_import("datasketch") if use_datasketch in ("auto", True) else None
        if ds is not None and use_datasketch is not False:
            self._near = _DatasketchLSH(ds)
            self.backend = "datasketch"
        else:
            self._near = _FallbackLSH()
            self.backend = "fallback"
        logger.debug(f"dedup: near-dup backend = {self.backend}")

    def add(self, text: str) -> tuple[bool, str]:
        """Index `text`; return (is_duplicate, reason). No-op when disabled."""
        if not self.enabled:
            return False, ""
        h = _exact_hash(text)
        if h in self._seen_exact:
            return True, "exact duplicate"
        self._seen_exact.add(h)
        return self._near.add(text)

    def save_state(self, path: str) -> None:
        """Persist exact-hash set to disk for crash-safe resume.

        Only the SHA256 set is checkpointed (not the near-dup LSH index, which
        is fast to rebuild). On a restart near-dup detection starts fresh, but
        exact duplicates are still caught across runs.
        """
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self._seen_exact, f)
        logger.debug(f"dedup: saved {len(self._seen_exact):,} hashes -> {path}")

    def load_state(self, path: str) -> None:
        """Restore exact-hash set saved by save_state()."""
        if not os.path.exists(path):
            return
        with open(path, "rb") as f:
            self._seen_exact = pickle.load(f)
        logger.info(f"dedup: loaded {len(self._seen_exact):,} hashes from {path}")
