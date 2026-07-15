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
import json
import os
import re

from . import common
from .common import logger, try_import

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

    def __init__(self, num_perm=None, threshold=None):
        num_perm = num_perm if num_perm is not None else common.MINHASH_PERM
        self.threshold = threshold if threshold is not None else common.NEAR_DUP_THRESHOLD
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
        sh = _shingles(text, common.SHINGLE_SIZE)
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
            if self._similarity(sig, self._sigs[idx]) >= self.threshold:
                return True, "near-duplicate (minhash)"
        # not a dup -> index it
        new_id = len(self._sigs)
        self._sigs.append(sig)
        for bi, key in band_keys:
            self._buckets[bi].setdefault(key, []).append(new_id)
        return False, ""


class _DatasketchLSH:
    """Near-dup index backed by datasketch MinHashLSH."""

    def __init__(self, datasketch, num_perm=None, threshold=None):
        num_perm = num_perm if num_perm is not None else common.MINHASH_PERM
        threshold = threshold if threshold is not None else common.NEAR_DUP_THRESHOLD
        self._ds = datasketch
        self.num_perm = num_perm
        self.lsh = datasketch.MinHashLSH(threshold=threshold, num_perm=num_perm)
        self._n = 0

    def _minhash(self, text: str):
        mh = self._ds.MinHash(num_perm=self.num_perm)
        for sh in _shingles(text, common.SHINGLE_SIZE):
            mh.update(sh.encode("utf-8"))
        return mh

    def add(self, text: str) -> tuple[bool, str]:
        sh = _shingles(text, common.SHINGLE_SIZE)
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

    def __init__(self, use_datasketch="auto", enabled: bool = True, near: bool = True):
        self.enabled = enabled
        self.near_enabled = near
        self._seen_exact: set[str] = set()
        if not enabled:
            self._near = None
            self.backend = "disabled"
            return
        if not near:
            # Exact-only: byte-identical (normalized) duplicates are removed, but
            # fuzzy near-dup matching is off, so similar-but-distinct records are
            # kept. Skips building the MinHash/LSH index entirely (faster, lighter).
            self._near = None
            self.backend = "exact-only"
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
        if self._near is None:                 # exact-only: no fuzzy matching
            return False, ""
        return self._near.add(text)

    def save_state(self, path: str) -> None:
        """Persist the exact-hash set to disk (JSON) for crash-safe resume.

        Only the SHA256 set is checkpointed (not the near-dup LSH index, which is
        fast to rebuild). JSON, not pickle: the checkpoint is rebuilt/loaded by
        the pipeline, and deserializing an unvetted pickle is a code-execution
        risk (threat model Stage 2: "Deduplication Index Corruption").
        """
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "exact": sorted(self._seen_exact)}, f)
        os.replace(tmp, path)
        logger.debug(f"dedup: saved {len(self._seen_exact):,} hashes -> {path}")

    def load_state(self, path: str) -> None:
        """Restore the exact-hash set saved by save_state().

        Validates the payload (a list of 64-char hex digests); a malformed or
        legacy file is ignored with a warning rather than trusted.
        """
        if not os.path.exists(path):
            return
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
            hashes = doc["exact"] if isinstance(doc, dict) else doc
            valid = {h for h in hashes
                     if isinstance(h, str) and len(h) == 64
                     and all(c in "0123456789abcdef" for c in h)}
        except (ValueError, KeyError, TypeError, OSError) as ex:
            logger.warning(f"dedup: ignoring unreadable checkpoint {path} "
                           f"({type(ex).__name__}); starting fresh")
            return
        self._seen_exact = valid
        logger.info(f"dedup: loaded {len(self._seen_exact):,} hashes from {path}")
