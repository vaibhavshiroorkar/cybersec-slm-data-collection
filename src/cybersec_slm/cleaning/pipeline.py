#!/usr/bin/env python3
"""Pipeline — runs the cleaning stages in flowchart order over data/raw.

    Sanitize -> Anomaly Check -> Dedup -> PII Removal -> Language filter -> data/clean/

Reads the ingestion output under data/raw/ and mirrors its layout into
data/clean/ (passed), flagged/ (behavioral anomalies for annotation) and dropped/
(structural + dedup + language drops, each annotated with a reason). A per-file
report is written to logs/clean_report.csv.
"""

from __future__ import annotations

import csv
import json
import os
import tempfile
import time

from . import anomaly, sanitize, textmap
from .common import (
    LOGS,
    OUT_CLEAN_DATA,
    OUT_DROPPED,
    OUT_FLAGGED,
    OUT_STAGES,
    PARSE_ERROR,
    RAW_DATA,
    REPORTS,
    JsonlWriter,
    find_input_files,
    iter_jsonl,
    json_dumps,
    logger,
    text_of,
)
from .dedup import Deduper
from .langfilter import LangFilter
from .pii import Redactor
from .translate import Translator

DEDUP_CKPT = os.path.join(LOGS, "dedup_checkpoint.txt")    # exact-hash journal
# The pre-journal format. Kept only so reset_dedup_state can clear it: a stale
# JSON checkpoint left beside the new one would never be read (the journal path
# differs) but would sit there looking authoritative.
DEDUP_CKPT_LEGACY = os.path.join(LOGS, "dedup_checkpoint.json")
DEDUP_DONE = os.path.join(LOGS, "dedup_done.json")         # files finished this pass
DEDUP_CKPT_INTERVAL_S = 30.0                               # min seconds between checkpoints

REPORT_COLS = ["sub_domain", "source", "file", "in", "mapped_text",
               "excluded_no_text", "sanitized", "struct_fixed", "struct_dropped",
               "behavioral_flagged", "exact_dups", "near_dups", "pii_redacted",
               "translated", "non_en_dropped", "out"]


def _annotate(rec, sub, source, relfile, stage, reason):
    out = dict(rec)
    out["_sub_domain"] = sub
    out["_source"] = source
    out["_file"] = relfile
    out["_stage"] = stage
    out["_reason"] = reason
    return out


def _new_counts():
    return {k: 0 for k in REPORT_COLS[3:]}


def clean_files(files, *, deduper, redactor, langf, translator, out_cleaned,
                out_flagged, out_dropped, limit: int | None = None,
                drop_non_english: bool = False) -> list[dict]:
    """Run the cleaning stages over `files` into the given output roots.

    `files` is an iterable of (abs_path, sub_domain, source, rel) as produced by
    `find_input_files`. The stateful objects (deduper/redactor/langf/translator)
    are passed in so callers control sharing — the parallel per-source worker
    passes a disabled deduper (`clean_one_source`), because global cross-source
    dedup runs later in one pass (`final_global_dedup`). Returns report rows.

    ``drop_non_english`` flips the language policy: by default a confidently
    non-allowed-language record is translated into English and kept; when True it
    is dropped instead (no translator call), which also avoids the slow, sometimes
    failing translation service on corpora that are already almost entirely English.
    """
    rows: list[dict] = []
    for entry in files:
        # A file entry is (abs_path, sub_domain, source, out_rel) plus an OPTIONAL
        # (line_start, line_end) window. The window lets a caller shard one big
        # file across worker processes: each shard reads only [start, end) and
        # writes to its own `out_rel` (e.g. "…/file.p03.jsonl"), so shards never
        # collide. `ap` is always the real input; `rel` only names the output.
        ap, sub, source, rel = entry[0], entry[1], entry[2], entry[3]
        win_start = entry[4] if len(entry) > 4 else 0
        win_end = entry[5] if len(entry) > 5 else None
        c = _new_counts()
        cw = JsonlWriter(os.path.join(out_cleaned, rel))
        fw = JsonlWriter(os.path.join(out_flagged, rel))
        dw = JsonlWriter(os.path.join(out_dropped, rel))
        try:
            for i, rec in enumerate(iter_jsonl(ap)):
                if i < win_start:
                    continue
                if win_end is not None and i >= win_end:
                    break
                if limit is not None and (i - win_start) >= limit:
                    break
                c["in"] += 1

                if rec.get(PARSE_ERROR):
                    c["struct_dropped"] += 1
                    dw.write(_annotate(rec, sub, source, rel, "anomaly", "json parse error"))
                    continue

                # Build `text` from prose columns when absent; feature-table rows
                # (no prose column) are excluded from the text corpus.
                mapped, tfield = textmap.to_text(rec)
                if mapped is None:
                    c["excluded_no_text"] += 1
                    continue
                if tfield != "text":
                    c["mapped_text"] += 1
                    rec = {**rec, "text": mapped, "_text_field": tfield}

                rec2, changed = sanitize.sanitize_record(rec)
                if changed:
                    c["sanitized"] += 1

                bucket, reason = anomaly.classify(rec2)
                if bucket == "structural":
                    c["struct_dropped"] += 1
                    dw.write(_annotate(rec2, sub, source, rel, "anomaly", reason))
                    continue
                # struct_fixed = sanitize rescued a structurally-broken record. An
                # unchanged record classifies identically pre/post, so the (heavy)
                # pre-sanitize classify runs only for changed survivors — it exists
                # purely for this counter.
                if changed and anomaly.classify(rec)[0] == "structural":
                    c["struct_fixed"] += 1
                if bucket == "behavioral":
                    c["behavioral_flagged"] += 1
                    fw.write(_annotate(rec2, sub, source, rel, "anomaly", reason))
                    continue

                # One text extraction per record, threaded through the remaining
                # stages (text_of rescans fields + strips on every call).
                txt = text_of(rec2)
                is_dup, dreason = deduper.add(txt)
                if is_dup:
                    if "exact" in dreason:
                        c["exact_dups"] += 1
                    else:
                        c["near_dups"] += 1
                    dw.write(_annotate(rec2, sub, source, rel, "dedup", dreason))
                    continue

                new_text, npii = redactor.redact(txt)
                if npii:
                    c["pii_redacted"] += 1
                    rec2["text"] = new_text
                    txt = new_text

                lang = langf.detect(txt)
                if not langf.lang_allowed(lang):
                    if drop_non_english:
                        # Policy: drop non-allowed-language records outright.
                        c["non_en_dropped"] += 1
                        dw.write(_annotate(rec2, sub, source, rel, "langfilter",
                                           f"non-allowed language (dropped): {lang}"))
                        continue
                    # Default: translate into English and keep, rather than
                    # dropping. Drop only if translation is impossible.
                    translated, ok = translator.translate(txt, src=lang)
                    if ok:
                        c["translated"] += 1
                        rec2["text"] = translated
                        rec2["_orig_lang"] = lang
                    else:
                        c["non_en_dropped"] += 1
                        dw.write(_annotate(rec2, sub, source, rel, "langfilter",
                                           f"non-allowed language (untranslatable): {lang}"))
                        continue

                cw.write(rec2)
                c["out"] += 1
        finally:
            cw.close(); fw.close(); dw.close()

        logger.info(f"  {rel}: in={c['in']} out={c['out']} "
                    f"mapped={c['mapped_text']} excluded={c['excluded_no_text']} "
                    f"flagged={c['behavioral_flagged']} "
                    f"dropped={c['struct_dropped']+c['exact_dups']+c['near_dups']+c['non_en_dropped']}")
        rows.append({"sub_domain": sub, "source": source, "file": rel, **c})
    return rows


# Process-local cache of the stateless cleaning transformers. Building a Redactor
# (Presidio + spaCy) or LangFilter (fastText model) costs seconds and hundreds of
# MB, so a pooled worker builds each ONCE and reuses it across every source it
# handles instead of paying that cost per source. Keyed by the factory class so a
# monkeypatched stub in tests transparently rebuilds. The Deduper is intentionally
# NOT cached — it is stateful and created (disabled) per source.
_cleaner_cache: dict = {}


def _cleaner(factory):
    """Return a process-cached instance of `factory` (built once, then reused)."""
    inst = _cleaner_cache.get(factory)
    if inst is None:
        inst = factory()
        _cleaner_cache[factory] = inst
    return inst


def reset_cleaner_cache() -> None:
    """Drop the cached transformers (used by tests; harmless in production)."""
    _cleaner_cache.clear()


def _source_files(source_dir: str, raw_root: str) -> list[tuple[str, str, str, str]]:
    """One source folder's .jsonl inputs as (abs_path, sub_domain, source, rel).

    Scans only `source_dir`, but names each output by its path relative to
    `raw_root`, so data/clean mirrors data/raw. Scoping the walk is what keeps a
    clean pass affordable: data/raw holds millions of non-.jsonl fetch artifacts
    beside a few hundred .jsonl inputs, so walking the whole tree costs minutes —
    a cost that would otherwise be paid once per source, in every worker.
    """
    source_dir = os.path.abspath(source_dir)
    raw_root = os.path.abspath(raw_root)
    files: list[tuple[str, str, str, str]] = []
    for ap, _sub, _source, _rel in find_input_files(source_dir):
        rel = os.path.relpath(ap, raw_root).replace("\\", "/")
        parts = rel.split("/")
        sub = parts[0] if parts else "unknown"
        source = parts[1] if len(parts) > 2 else (parts[0] if parts else "unknown")
        files.append((ap, sub, source, rel))
    return files


# Sharding thresholds. The pool parallelises per SOURCE and clean_files walks a
# source's files in order, so one huge file pins exactly one worker: on this
# corpus a single 20 GB source needed ~50h on its worker while the other five sat
# idle. Splitting that file into windows lets the pool work on it together.
#
# Only files past MIN_BYTES are considered, for two reasons: sharding a small file
# buys nothing, and deciding to shard costs a full line count (records, not bytes,
# are what a window addresses) which is far too expensive to pay for every file.
SHARD_MIN_BYTES = 256 * 1024 * 1024
SHARD_TARGET_RECORDS = 20_000
# Record count alone is the wrong size for a shard: this corpus holds files whose
# records average ~400 KB, where 20k records is still an 8 GB shard and one worker
# is back to owning the whole tail. Cap a shard by bytes too, using the file's own
# mean record size, so a shard is a similar amount of WORK whatever the row shape.
SHARD_TARGET_BYTES = 256 * 1024 * 1024


def count_records(path: str) -> int:
    """Line count of a .jsonl, read as bytes (never decodes, never builds strings)."""
    n = 0
    try:
        with open(path, "rb") as f:
            for _ in f:
                n += 1
    except OSError:
        return 0
    return n


def shard_files(files, *, min_bytes: int | None = None,
                target_records: int | None = None) -> list[tuple]:
    """Expand ``(ap, sub, source, rel)`` inputs into ``(..., out_rel, start, end)``.

    A file under ``min_bytes`` yields exactly one window covering all of it, so
    the overwhelming majority of sources keep their current single output file and
    layout. A file over it is split into ``target_records``-sized windows, each
    writing its own ``<stem>.pNNN.jsonl``.

    The shard name is chosen so the *sorted* order of data/clean is unchanged:
    ``a.p000.jsonl`` still sorts after any earlier file and before ``b.jsonl``,
    exactly where ``a.jsonl`` sat. That matters because ``final_global_dedup``
    walks in sorted order and keeps the first copy of a duplicate — reordering the
    tree would silently change which source a shared record is attributed to.

    Records themselves are untouched: a window only selects which records a worker
    reads, so the cleaned output is the same set either way.

    The thresholds resolve at call time, not as default arguments: a default binds
    the module constant once at import and could never be tuned afterwards.
    """
    min_bytes = SHARD_MIN_BYTES if min_bytes is None else min_bytes
    target_records = SHARD_TARGET_RECORDS if target_records is None else target_records
    out: list[tuple] = []
    for ap, sub, source, rel in files:
        try:
            size = os.path.getsize(ap)
        except OSError:
            size = 0
        if size < min_bytes:
            out.append((ap, sub, source, rel, 0, None))   # whole file, one window
            continue
        total = count_records(ap)
        if total <= 1:
            out.append((ap, sub, source, rel, 0, None))
            continue
        # Whichever limit bites first: row count for ordinary records, bytes for
        # the huge-record files where 20k rows would still be a multi-GB shard.
        by_bytes = max(1, int(SHARD_TARGET_BYTES // max(size // total, 1)))
        step = max(1, min(target_records, by_bytes))
        if total <= step:
            out.append((ap, sub, source, rel, 0, None))
            continue
        stem = rel[:-6] if rel.endswith(".jsonl") else rel
        for i, start in enumerate(range(0, total, step)):
            end = min(start + step, total)
            out.append((ap, sub, source, f"{stem}.p{i:03d}.jsonl", start, end))
    return out


def clean_chunk(chunk: tuple, *, clean_data_dir: str | None = None,
                flagged_dir: str | None = None, dropped_dir: str | None = None,
                limit: int | None = None,
                drop_non_english: bool = False) -> list[dict]:
    """Clean one ``(ap, sub, source, out_rel, start, end)`` window.

    The per-source deduper is disabled here exactly as it is for a whole source
    (cross-source dedup is deferred to :func:`final_global_dedup`), so splitting a
    file across workers cannot change what dedup does — there is no per-source
    dedup state for a shard boundary to divide.

    Every output root is an argument that resolves at call time. A pool worker is
    a *spawned* process: it re-imports this module and rebuilds ``OUT_CLEAN_DATA``
    from the real data root, so a worker that read the module global would ignore
    a caller's redirected paths entirely and write into the live corpus.
    """
    deduper = Deduper(enabled=False)
    return clean_files(
        [chunk], deduper=deduper, redactor=_cleaner(Redactor),
        langf=_cleaner(LangFilter), translator=_cleaner(Translator),
        out_cleaned=clean_data_dir if clean_data_dir is not None else OUT_CLEAN_DATA,
        out_flagged=flagged_dir if flagged_dir is not None else OUT_FLAGGED,
        out_dropped=dropped_dir if dropped_dir is not None else OUT_DROPPED,
        limit=limit, drop_non_english=drop_non_english)


def clean_one_source(source_dir: str, *, raw_root: str = RAW_DATA,
                     clean_data_dir: str = OUT_CLEAN_DATA,
                     limit: int | None = None,
                     drop_non_english: bool = False) -> list[dict]:
    """Clean a single source's .jsonl files into `data/clean/` (no global dedup).

    Used by the parallel per-source worker. Global cross-source dedup is deferred
    to `final_global_dedup`; here the deduper is disabled so each worker stays
    isolated. Output mirrors the data/raw layout (rel paths are relative to
    `raw_root`). Returns report rows for the parent to aggregate.

    The PII/language/translation transformers are stateless across sources, so
    they are reused from a process-local cache (`_cleaner`) rather than rebuilt for
    every source.
    """
    files = _source_files(source_dir, raw_root)
    if not files:
        return []
    deduper = Deduper(enabled=False)
    redactor = _cleaner(Redactor)
    langf = _cleaner(LangFilter)
    translator = _cleaner(Translator)
    return clean_files(files, deduper=deduper, redactor=redactor, langf=langf,
                       translator=translator, out_cleaned=clean_data_dir,
                       out_flagged=OUT_FLAGGED, out_dropped=OUT_DROPPED,
                       limit=limit, drop_non_english=drop_non_english)


def clean_source_folder(folder: str, *, redactor, langf, translator,
                        raw_root: str = RAW_DATA,
                        clean_data_dir: str = OUT_CLEAN_DATA,
                        flagged_dir: str = OUT_FLAGGED,
                        dropped_dir: str = OUT_DROPPED,
                        limit: int | None = None,
                        drop_non_english: bool = False) -> list[dict]:
    """Clean ONE already-fetched source folder into data/clean/ (dedup disabled).

    Scans only `folder` (O(files-in-source), not the whole raw tree) but computes
    `rel` relative to `raw_root` so the data/clean/ layout mirrors data/raw/.
    The caller supplies the (once-built) transformers so the heavy models load a
    single time in the parent. Cross-source global dedup is deferred to
    `final_global_dedup`, so the deduper here is disabled. Returns report rows.
    """
    files = _source_files(folder, raw_root)
    if not files:
        return []
    deduper = Deduper(enabled=False)
    return clean_files(files, deduper=deduper, redactor=redactor, langf=langf,
                       translator=translator, out_cleaned=clean_data_dir,
                       out_flagged=flagged_dir, out_dropped=dropped_dir, limit=limit,
                       drop_non_english=drop_non_english)


def reset_dedup_state() -> None:
    """Remove the dedup checkpoint + done-list so the next pass starts fresh.

    Called at the start of a fresh (non-resume) build so a stale checkpoint from a
    previous corpus can never flag this build's records as duplicates.
    """
    for p in (DEDUP_CKPT, DEDUP_CKPT_LEGACY, DEDUP_DONE):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass


def _load_dedup_done(path: str) -> set[str]:
    if not os.path.exists(path):
        return set()
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return {str(x) for x in data} if isinstance(data, list) else set()
    except (ValueError, OSError):
        return set()


def _save_dedup_done(path: str, done: set[str]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(sorted(done), f)
    os.replace(tmp, path)


def final_global_dedup(clean_data_dir: str = OUT_CLEAN_DATA, *,
                       resume: bool = False) -> dict:
    """One cross-source dedup pass over `data/clean/`, rewriting files in place.

    The per-source workers skip global dedup, so this single pass (run once in
    the parent after the pool drains) is what catches duplicates shared across
    sources. Removed records are appended to `dropped/` with a `dedup` reason.

    Deterministic and resumable. Files are processed in sorted order, so which of
    two cross-source duplicates survives ("first wins") is stable across runs. The
    exact-hash set is checkpointed (DEDUP_CKPT) and finished files recorded
    (DEDUP_DONE) after each file. ``resume=True`` reloads both and skips
    already-finished files, so a crashed pass restarts where it stopped instead of
    from zero; a fresh run (default) clears the sidecars first. Only the exact-hash
    set is persisted (cheap to keep), so on a resumed pass near-duplicate matching
    against already-finished files is not restored — exact dedup is.

    Corpus policy: cross-source dedup is **exact-only** (``Deduper(near=False)``).
    Byte-identical (normalized) duplicates across sources are removed; fuzzy
    near-duplicates are intentionally kept, because near-dup matching collapsed too
    many similar-but-distinct cyber records (templated CVE text, MITRE techniques,
    log lines). Run ``cybersec-slm clean dedup`` for a near-dup diagnostic on demand.
    """
    deduper = Deduper(near=False)
    if resume:
        deduper.load_state(DEDUP_CKPT)
        done = _load_dedup_done(DEDUP_DONE)
        if done:
            logger.info(f"final dedup: resuming — {len(done)} files already done")
    else:
        reset_dedup_state()
        done = set()

    stats = {"files": 0, "in": 0, "kept": 0, "exact_dups": 0, "near_dups": 0,
             "skipped": 0}
    logger.info(f"final global dedup over {clean_data_dir} "
                f"(backend={deduper.backend})")
    last_ckpt = time.monotonic()
    # Sorted for determinism: cross-source "first duplicate wins" must not depend
    # on os.walk order.
    for ap, sub, source, rel in sorted(find_input_files(clean_data_dir),
                                       key=lambda t: t[3]):
        if rel in done:
            stats["skipped"] += 1
            continue
        stats["files"] += 1
        # Append (don't truncate): the per-source clean already wrote structural
        # / language drops to dropped/<rel>; cross-source dups go to the same file.
        dropped_path = os.path.join(OUT_DROPPED, rel)
        dropped_fh = None
        # ".jsonl.tmp" so a crash-orphaned temp is NOT picked up as a data file by
        # find_input_files (which matches *.jsonl) on the next run.
        fd, tmp = tempfile.mkstemp(suffix=".jsonl.tmp", dir=os.path.dirname(ap))
        os.close(fd)
        try:
            with open(tmp, "w", encoding="utf-8") as out:
                for rec in iter_jsonl(ap):
                    if rec.get(PARSE_ERROR):
                        continue
                    stats["in"] += 1
                    is_dup, dreason = deduper.add(text_of(rec))
                    if is_dup:
                        if "exact" in dreason:
                            stats["exact_dups"] += 1
                        else:
                            stats["near_dups"] += 1
                        if dropped_fh is None:
                            os.makedirs(os.path.dirname(dropped_path) or ".", exist_ok=True)
                            dropped_fh = open(dropped_path, "a", encoding="utf-8")
                        dropped_fh.write(json_dumps(
                            _annotate(rec, sub, source, rel, "dedup", dreason)) + "\n")
                        continue
                    out.write(json_dumps(rec) + "\n")
                    stats["kept"] += 1
        finally:
            if dropped_fh is not None:
                dropped_fh.close()
        os.replace(tmp, ap)
        done.add(rel)
        # Amortized checkpoint: persist at most every DEDUP_CKPT_INTERVAL_S so a
        # large corpus doesn't re-serialize the whole hash set once per file. A
        # crash loses at most that interval of dedup work; those files are simply
        # reprocessed on resume (idempotent, since their duplicates are gone).
        now = time.monotonic()
        if now - last_ckpt >= DEDUP_CKPT_INTERVAL_S:
            deduper.save_state(DEDUP_CKPT)
            _save_dedup_done(DEDUP_DONE, done)
            last_ckpt = now
    # Final checkpoint so a cleanly finished pass is fully recorded for resume.
    if stats["files"]:
        deduper.save_state(DEDUP_CKPT)
        _save_dedup_done(DEDUP_DONE, done)
    logger.info("final dedup: files={files} skipped={skipped} in={in} kept={kept} "
                "exact_dups={exact_dups} near_dups={near_dups}".format(**stats))
    return stats


def _report_path() -> str:
    return os.path.join(REPORTS, "clean_report.csv")


def _coerce_counts(row: dict) -> dict:
    """A report row with its counter cells as ints.

    CSV gives every cell back as a string; the in-memory rows a pass produces hold
    ints. Merging the two without this makes `_write_report`'s totalling add a str
    to an int.
    """
    out = dict(row)
    for col in REPORT_COLS[3:]:
        try:
            out[col] = int(float(out.get(col) or 0))
        except (TypeError, ValueError):
            out[col] = 0
    return out


def read_report_rows() -> list[dict]:
    """Per-source rows already in the clean report (the TOTAL row excluded)."""
    path = _report_path()
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8", newline="") as f:
            return [_coerce_counts(r) for r in csv.DictReader(f)
                    if r.get("sub_domain") != "TOTAL"]
    except OSError:
        return []


def merge_report_rows(new_rows: list[dict]) -> list[dict]:
    """``new_rows`` merged over the rows already in the report, keyed by ``file``.

    A pass only holds the rows for the sources it actually cleaned: a ``--resume``
    run skips the rest via the ledger, and a selective run only touches the chosen
    sub-domains. Writing the report from that subset alone silently shrank it to
    those sources, so every counter derived from it described part of the corpus
    while claiming to describe all of it. Keying on ``file`` means a re-cleaned
    source updates its row instead of duplicating it, which keeps the merge
    idempotent across repeated resumes.
    """
    merged = {r.get("file"): r for r in read_report_rows()}
    for r in new_rows:
        merged[r.get("file")] = r
    return list(merged.values())


def _write_report(rows: list[dict]) -> str:
    os.makedirs(REPORTS, exist_ok=True)
    path = _report_path()
    totals = _new_counts()
    for r in rows:
        for k in totals:
            totals[k] += r.get(k, 0)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=REPORT_COLS)
        w.writeheader()
        for r in rows:
            w.writerow(r)
        w.writerow({"sub_domain": "TOTAL", "source": "", "file": f"{len(rows)} files",
                    **totals})
    logger.info(f"report -> {path}")
    logger.info("TOTAL " + " ".join(f"{k}={totals[k]}" for k in
                ("in", "out", "mapped_text", "excluded_no_text", "struct_dropped",
                 "behavioral_flagged", "exact_dups", "near_dups", "pii_redacted",
                 "translated", "non_en_dropped")))
    return path


# ---------------------------------------------------- single-stage diagnostics
def run_single_stage(stage: str, input_dir: str = RAW_DATA,
                     limit: int | None = None) -> dict:
    """Apply one stage across the input into _stages/<stage>/ for inspection.

    Not the production path (that is the parallel per-source worker); a debugging
    aid for looking at one transform in isolation.
    """
    if stage not in ("sanitize", "dedup", "pii", "lang"):
        raise ValueError(f"unknown stage: {stage}")
    deduper = Deduper() if stage == "dedup" else None
    redactor = Redactor() if stage == "pii" else None
    langf = LangFilter() if stage == "lang" else None
    translator = Translator() if stage == "lang" else None
    stats = {"in": 0, "out": 0, "affected": 0}

    for ap, _sub, _source, rel in find_input_files(input_dir):
        w = JsonlWriter(os.path.join(OUT_STAGES, stage, rel))
        try:
            for i, rec in enumerate(iter_jsonl(ap)):
                if limit is not None and i >= limit:
                    break
                if rec.get(PARSE_ERROR):
                    continue
                stats["in"] += 1
                if stage == "sanitize":
                    rec2, changed = sanitize.sanitize_record(rec)
                    stats["affected"] += int(changed)
                    w.write(rec2); stats["out"] += 1
                elif stage == "dedup":
                    is_dup, _ = deduper.add(text_of(rec))
                    if is_dup:
                        stats["affected"] += 1
                        continue
                    w.write(rec); stats["out"] += 1
                elif stage == "pii":
                    nt, n = redactor.redact(text_of(rec))
                    if n:
                        stats["affected"] += 1
                        rec = {**rec, "text": nt}
                    w.write(rec); stats["out"] += 1
                elif stage == "lang":
                    lang = langf.detect(text_of(rec))
                    if langf.lang_allowed(lang):
                        w.write(rec); stats["out"] += 1
                    else:
                        translated, ok = translator.translate(text_of(rec), src=lang)
                        if ok:
                            stats["affected"] += 1
                            rec = {**rec, "text": translated, "_orig_lang": lang}
                            w.write(rec); stats["out"] += 1
                        else:
                            stats["affected"] += 1
        finally:
            w.close()
    logger.info(f"stage '{stage}': in={stats['in']} out={stats['out']} "
                f"affected={stats['affected']} -> {os.path.join(OUT_STAGES, stage)}")
    return stats


def build_report_from_outputs() -> str:
    """Recount existing data/clean/flagged/dropped trees into a summary line."""
    def count_tree(root):
        n = 0
        for r, _d, fs in os.walk(root):
            for fn in fs:
                if fn.endswith(".jsonl"):
                    with open(os.path.join(r, fn), encoding="utf-8", errors="replace") as f:
                        n += sum(1 for ln in f if ln.strip())
        return n
    cleaned = count_tree(OUT_CLEAN_DATA)
    flagged = count_tree(OUT_FLAGGED)
    dropped = count_tree(OUT_DROPPED)
    logger.info(f"outputs -> cleaned={cleaned} flagged={flagged} dropped={dropped}")
    return f"cleaned={cleaned} flagged={flagged} dropped={dropped}"

