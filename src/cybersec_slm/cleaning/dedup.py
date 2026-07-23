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
_HEX64_RE = re.compile(r"[0-9a-f]{64}")
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
        # Hashes seen since the last save_state, i.e. what the next flush has to
        # append. Keeping this list is what lets the checkpoint be O(new).
        self._unsaved: list[str] = []
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
        self._unsaved.append(h)
        if self._near is None:                 # exact-only: no fuzzy matching
            return False, ""
        return self._near.add(text)

    def save_state(self, path: str) -> None:
        """Append the hashes added since the last call to the checkpoint journal.

        Append-only, one 64-char hex digest per line. The previous format
        re-sorted and rewrote the WHOLE set on every flush, which the pipeline
        does every 30s: at 1M hashes that is 1.42s of sorting plus a 68 MB write
        each time, growing with the corpus. Appending is O(new) and leaves what is
        already on disk untouched.

        Only the SHA256 set is checkpointed (not the near-dup LSH index, which is
        fast to rebuild). Plain text, not pickle: the checkpoint is loaded back by
        the pipeline, and deserializing an unvetted pickle is a code-execution
        risk (threat model Stage 2: "Deduplication Index Corruption").
        """
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.writelines(f"{h}\n" for h in self._unsaved)
        n = len(self._unsaved)
        self._unsaved.clear()
        logger.debug(f"dedup: appended {n:,} hashes -> {path} "
                     f"({len(self._seen_exact):,} total)")

    def load_state(self, path: str) -> None:
        """Restore the exact-hash set written by :meth:`save_state`.

        Every line is validated as a 64-char hex digest, so a torn final line
        from a crash mid-append is skipped rather than trusted — which is what
        makes the append-only journal crash-safe. A legacy JSON checkpoint has no
        valid lines and is therefore ignored, exactly like any other junk.
        """
        if not os.path.exists(path):
            return
        try:
            with open(path, encoding="utf-8") as f:
                valid = {ln for ln in (line.strip() for line in f)
                         if _HEX64_RE.fullmatch(ln)}
        except OSError as ex:
            logger.warning(f"dedup: ignoring unreadable checkpoint {path} "
                           f"({type(ex).__name__}); starting fresh")
            return
        self._seen_exact = valid
        self._unsaved = []          # everything just loaded is already on disk
        logger.info(f"dedup: loaded {len(self._seen_exact):,} hashes from {path}")

