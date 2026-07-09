#!/usr/bin/env python3
"""Rebuild the final dataset from all available raw data, with NO domain caps,
using parallel chunked cleaning so a 2.5M-record corpus finishes in hours.

Why this exists
---------------
The stock ``clean_raw_tree`` cleans sequentially in one process; on a multi-
million-record corpus that is dominated by Presidio PII (spaCy NER per record)
and takes ~2 days.  This driver instead:

  * splits the raw tree into record-balanced CHUNKS (big files are sharded), and
    cleans them across a process pool (each worker builds Presidio ONCE) -- an
    ~Nx speedup on an N-core box;
  * sets a PII size guard (``CYBERSEC_SLM_PII_MAX_CHARS``) so huge smart-contract
    blobs skip Presidio and use the linear regex path;
  * disables the flaky online translator (``CYBERSEC_SLM_TRANSLATE=off``) so a
    dead network can't stall the run;
  * skips ealvaradob's ``urls.jsonl`` / ``texts.jsonl``, which are a strict
    subset of its ``combined_full.jsonl`` (global dedup would drop them anyway).

Then: cross-source global dedup -> EDA report (auto-rebalance OFF) -> normalize.

Run from the repo root:
    python tools/rebuild_nocap.py
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from concurrent.futures import ProcessPoolExecutor

# These must be set BEFORE importing cybersec_slm (config/env read at import).
os.environ.setdefault("EDA_AUTO_REBALANCE", "0")           # never auto-cap
os.environ.setdefault("CYBERSEC_SLM_TRANSLATE", "off")     # no network stalls
os.environ.setdefault("CYBERSEC_SLM_PII_MAX_CHARS", "10000")  # guard huge blobs

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if os.path.join(_ROOT, "src") not in sys.path:
    sys.path.insert(0, os.path.join(_ROOT, "src"))

CHUNK_RECORDS = 20_000          # target records per parallel chunk
DEFAULT_WORKERS = max(1, (os.cpu_count() or 4) - 2)   # leave 2 cores free

# ealvaradob files that are strictly contained in combined_full.jsonl.
_REDUNDANT_BASENAMES = {"urls.jsonl", "texts.jsonl", "webs.jsonl",
                        "combined_reduced.jsonl"}


def _banner(msg: str) -> None:
    print(f"\n{'=' * 72}\n  {msg}\n{'=' * 72}", flush=True)


def _count_lines(path: str) -> int:
    n = 0
    with open(path, "rb") as f:
        for _ in f:
            n += 1
    return n


def _raw_files() -> list[tuple]:
    """The raw (ap, sub, source, rel) files we actually clean (after exclusions)."""
    from cybersec_slm.cleaning.common import find_input_files
    from cybersec_slm import core

    out = []
    for ap, sub, source, rel in find_input_files(core.RAW_DATA):
        base = os.path.basename(ap)
        # `.original.jsonl` are pre-transform backups -> not inputs (would double).
        if base.endswith(".original.jsonl"):
            continue
        # ealvaradob urls/texts/webs are a subset of combined_full.jsonl.
        if "ealvaradob" in ap.replace("\\", "/") and base in _REDUNDANT_BASENAMES:
            continue
        out.append((ap, sub, source, rel))
    return out


def _wipe_reclean_targets(raw_files: list[tuple]) -> int:
    """Remove clean/<domain>/<source> for every source we're about to re-clean.

    Clears stale full-file outputs from earlier runs (and the killed run's partial
    shards) so they can't be double-counted, while preserving clean data for
    sources whose raw was already deleted (those dirs are never touched here).
    """
    from cybersec_slm import core

    targets = set()
    for _ap, _sub, _source, rel in raw_files:
        parts = rel.split("/")
        # clean tree mirrors raw: <domain>/<source>/...  (source dir = first 2)
        src_dir = os.path.join(core.CLEAN_DATA, *parts[:2]) if len(parts) >= 3 \
            else os.path.join(core.CLEAN_DATA, parts[0])
        targets.add(src_dir)
    for d in targets:
        shutil.rmtree(d, ignore_errors=True)
    return len(targets)


def _build_chunks() -> list[tuple]:
    """Enumerate raw files -> record-balanced (ap, sub, source, out_rel, s, e)."""
    chunks: list[tuple] = []
    for ap, sub, source, rel in _raw_files():
        total = _count_lines(ap)
        if total == 0:
            continue
        if total <= CHUNK_RECORDS:
            chunks.append((ap, sub, source, rel, 0, total))
            continue
        # Shard: each piece writes to <rel>.pNN.jsonl so outputs never collide.
        stem = rel[:-6] if rel.endswith(".jsonl") else rel
        for pi, start in enumerate(range(0, total, CHUNK_RECORDS)):
            end = min(start + CHUNK_RECORDS, total)
            shard_rel = f"{stem}.p{pi:03d}.jsonl"
            chunks.append((ap, sub, source, shard_rel, start, end))
    # Biggest chunks first so stragglers don't tail the run.
    chunks.sort(key=lambda t: t[5] - t[4], reverse=True)
    return chunks


def _clean_chunk(chunk: tuple) -> dict:
    """Worker: clean one (file, window) chunk. Runs in a pool worker process."""
    from cybersec_slm import core
    from cybersec_slm.cleaning.dedup import Deduper
    from cybersec_slm.cleaning.langfilter import LangFilter
    from cybersec_slm.cleaning.pii import Redactor
    from cybersec_slm.cleaning.translate import Translator
    from cybersec_slm.cleaning import pipeline as cp

    redactor = cp._cleaner(Redactor)       # built once per worker process
    langf = cp._cleaner(LangFilter)
    translator = cp._cleaner(Translator)
    rows = cp.clean_files(
        [chunk], deduper=Deduper(enabled=False), redactor=redactor,
        langf=langf, translator=translator, out_cleaned=core.CLEAN_DATA,
        out_flagged=core.FLAGGED, out_dropped=core.DROPPED)
    return {"in": sum(r.get("in", 0) for r in rows),
            "out": sum(r.get("out", 0) for r in rows)}


def _parallel_clean(workers: int) -> dict:
    # Clear stale clean output for re-cleaned sources (preserving deleted-raw
    # sources), then build record-balanced chunks.
    wiped = _wipe_reclean_targets(_raw_files())
    print(f"  cleared {wiped} clean source dir(s) for re-clean", flush=True)
    chunks = _build_chunks()
    total_records = sum(c[5] - c[4] for c in chunks)
    print(f"  {len(chunks)} chunks, {total_records:,} records, {workers} workers",
          flush=True)

    done_in = done_out = done_chunks = 0
    t0 = time.monotonic()
    with ProcessPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(_clean_chunk, chunks):
            done_in += res["in"]
            done_out += res["out"]
            done_chunks += 1
            if done_chunks % 10 == 0 or done_chunks == len(chunks):
                el = time.monotonic() - t0
                rate = done_in / el if el else 0
                eta = (total_records - done_in) / rate / 60 if rate else 0
                print(f"  [{done_chunks}/{len(chunks)}] in={done_in:,} "
                      f"out={done_out:,} {rate:.0f} rec/s  ETA~{eta:.0f} min",
                      flush=True)
    return {"in": done_in, "out": done_out, "chunks": len(chunks)}


def main() -> None:
    from cybersec_slm.core import CLEAN_DATA, FINAL_DATA
    from cybersec_slm.cleaning.pipeline import final_global_dedup, reset_dedup_state
    from cybersec_slm.eda.pipeline import run_eda
    from cybersec_slm.normalize.pipeline import run_normalization

    workers = int(os.environ.get("REBUILD_WORKERS", DEFAULT_WORKERS))
    t0 = time.monotonic()

    _banner("Step 1/5 - clearing data/final/ and dedup state")
    shutil.rmtree(FINAL_DATA, ignore_errors=True)
    os.makedirs(FINAL_DATA, exist_ok=True)
    reset_dedup_state()
    print("  cleared.", flush=True)

    _banner("Step 2/5 - parallel chunked cleaning of raw -> data/clean/")
    clean_result = _parallel_clean(workers)
    print(f"  clean done: {clean_result}  "
          f"[{(time.monotonic()-t0)/60:.1f} min]", flush=True)

    _banner("Step 3/5 - final global dedup over data/clean/")
    dedup_result = final_global_dedup(CLEAN_DATA, resume=False)
    print(f"  dedup: {dedup_result}  [{(time.monotonic()-t0)/60:.1f} min]",
          flush=True)

    _banner("Step 4/5 - EDA report (observe only, no cap)")
    try:
        eda = run_eda(enforce=False)
        print(f"  EDA passed={eda.get('passed')} "
              f"total={eda.get('metrics', {}).get('total')}", flush=True)
    except Exception as exc:
        print(f"  EDA raised (non-fatal): {exc}", flush=True)

    _banner("Step 5/5 - normalize -> data/final/dataset.jsonl")
    norm = run_normalization(resume=False)
    counts = norm.get("counts", {})
    print(f"\n  normalize counts: {counts}", flush=True)
    print(f"\n  FINAL written: {counts.get('written'):,} records", flush=True)
    print(f"  total wall time: {(time.monotonic()-t0)/60:.1f} min", flush=True)
    _banner("Done")


if __name__ == "__main__":
    main()
