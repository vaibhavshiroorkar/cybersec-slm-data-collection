#!/usr/bin/env python3
"""What is actually in ``data/final/dataset.jsonl``, read from the file itself.

The funnel's Final row used to take its records and sources from
``data/final/manifest.json``, but the manifest is only written when a whole
normalize pass finishes (``normalize.pipeline.main`` calls ``write_manifest`` at
the very end). During a run, and after any interrupted one, the manifest is
absent while the dataset is large and growing, so the row read "0 records" next
to a multi-gigabyte Size. Same reasoning the Raw and Cleaned rows already follow:
disk is the only figure that stays true across resumes.

Records, sources and tokens all come out of one pass, so they cannot disagree
with each other, which is the failure this replaces.

The dataset is append-only within a run (``normalize.pipeline._Sink``), so a scan
memoizes where it stopped and later scans parse only what was appended since.
That keeps a 5 GB corpus off the critical path of a 1s dashboard tick: the first
scan is a few seconds, every scan after it reads a few MB.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from ..core import json_loads, logger


@dataclass(frozen=True)
class FinalStats:
    """The final dataset's figures. All zero when it does not exist yet."""

    records: int = 0
    sources: int = 0
    tokens: int = 0
    size_mb: float = 0.0


@dataclass
class _Memo:
    """How far a previous scan got, and what it had counted by then."""

    offset: int = 0
    records: int = 0
    tokens: int = 0
    sources: set[str] = field(default_factory=set)


_MEMO: dict[str, _Memo] = {}
_ONE_MB = 1048576


def reset() -> None:
    """Drop every memo, so the next scan re-reads from byte zero."""
    _MEMO.clear()


def _memo_still_fits(fh, memo: _Memo, size: int) -> bool:
    """True when the file is still the one the memo describes.

    A shorter file has obviously been rewritten. A file that is merely *longer*
    is not proof of an append: a ``--no-resume`` run truncates and regrows, and
    can pass the old offset between two ticks. The memo's offset always sits just
    after a newline, so checking that byte is still a newline catches a regrow
    that a size comparison would wave through. One seek and one byte.
    """
    if size < memo.offset:
        return False
    if memo.offset == 0:
        return True
    fh.seek(memo.offset - 1)
    return fh.read(1) == b"\n"


def _consume(chunk: bytes) -> tuple[bytes, int]:
    """Split off the complete lines of ``chunk``, and how many bytes they span.

    A normalize worker may be mid-``write`` when the dashboard reads, so the tail
    of the file can be half a record. Only bytes up to the last newline are a
    record; the rest is left for the next scan, which sees it completed.
    """
    cut = chunk.rfind(b"\n")
    if cut < 0:
        return b"", 0
    return chunk[:cut + 1], cut + 1


def scan(path: str | None = None) -> FinalStats:
    """The final dataset's records, distinct sources, tokens and size.

    Parses only the bytes appended since the last call for this path. Safe to
    call while a normalize run is writing: a partially written trailing record is
    not counted until it is complete.
    """
    if path is None:
        from . import data
        path = os.path.join(data._final(), "dataset.jsonl")

    try:
        size = os.path.getsize(path)
    except OSError:
        return FinalStats()

    memo = _MEMO.get(path) or _Memo()
    try:
        with open(path, "rb") as fh:
            if not _memo_still_fits(fh, memo, size):
                memo = _Memo()          # rewritten: count it as the new file it is
            fh.seek(memo.offset)
            body, used = _consume(fh.read())
    except OSError as e:
        logger.debug(f"final_stats: {path}: {type(e).__name__}: {e}")
        return FinalStats()

    for line in body.splitlines():
        if not line.strip():
            continue
        try:
            rec = json_loads(line)
        except ValueError:
            continue                    # a malformed line is not worth a crash
        if not isinstance(rec, dict):
            continue
        memo.records += 1
        memo.sources.add(str(rec.get("source") or "?"))
        try:
            memo.tokens += int(rec.get("token_count") or 0)
        except (TypeError, ValueError):
            pass

    memo.offset += used
    _MEMO[path] = memo
    return FinalStats(records=memo.records, sources=len(memo.sources),
                      tokens=memo.tokens, size_mb=size / _ONE_MB)
