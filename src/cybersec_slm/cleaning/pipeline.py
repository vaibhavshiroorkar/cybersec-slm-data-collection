#!/usr/bin/env python3
"""Pipeline — runs the cleaning stages in flowchart order over data/raw.

    Sanitize -> Anomaly Check -> Dedup -> PII Removal -> Language filter -> data/clean/

Reads the extraction output under data/raw/ and mirrors its layout into
data/clean/ (passed), flagged/ (behavioral anomalies for annotation) and dropped/
(structural + dedup + language drops, each annotated with a reason). A per-file
report is written to logs/clean_report.csv.
"""

from __future__ import annotations

import csv
import json
import os
import tempfile

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
    logger,
    text_of,
)
from .dedup import Deduper
from .langfilter import LangFilter
from .pii import Redactor
from .translate import Translator

DEDUP_CKPT = os.path.join(LOGS, "dedup_checkpoint.json")

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
                checkpoint_path: str | None = None) -> list[dict]:
    """Run the cleaning stages over `files` into the given output roots.

    `files` is an iterable of (abs_path, sub_domain, source, rel) as produced by
    `find_input_files`. The stateful objects (deduper/redactor/langf/translator)
    are passed in so callers control sharing — one global deduper for `run_all`,
    a disabled per-source deduper for `clean_one_source`. Returns report rows.
    """
    rows: list[dict] = []
    for ap, sub, source, rel in files:
        c = _new_counts()
        cw = JsonlWriter(os.path.join(out_cleaned, rel))
        fw = JsonlWriter(os.path.join(out_flagged, rel))
        dw = JsonlWriter(os.path.join(out_dropped, rel))
        try:
            for i, rec in enumerate(iter_jsonl(ap)):
                if limit is not None and i >= limit:
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

                pre_bucket, _ = anomaly.classify(rec)
                rec2, changed = sanitize.sanitize_record(rec)
                if changed:
                    c["sanitized"] += 1

                bucket, reason = anomaly.classify(rec2)
                if bucket == "structural":
                    c["struct_dropped"] += 1
                    dw.write(_annotate(rec2, sub, source, rel, "anomaly", reason))
                    continue
                if pre_bucket == "structural":      # sanitize rescued it
                    c["struct_fixed"] += 1
                if bucket == "behavioral":
                    c["behavioral_flagged"] += 1
                    fw.write(_annotate(rec2, sub, source, rel, "anomaly", reason))
                    continue

                is_dup, dreason = deduper.add(text_of(rec2))
                if is_dup:
                    if "exact" in dreason:
                        c["exact_dups"] += 1
                    else:
                        c["near_dups"] += 1
                    dw.write(_annotate(rec2, sub, source, rel, "dedup", dreason))
                    continue

                new_text, npii = redactor.redact(text_of(rec2))
                if npii:
                    c["pii_redacted"] += 1
                    rec2["text"] = new_text

                lang = langf.detect(text_of(rec2))
                if not langf.lang_allowed(lang):
                    # Confidently non-allowed: translate into English and keep,
                    # rather than dropping. Drop only if translation is impossible.
                    translated, ok = translator.translate(text_of(rec2), src=lang)
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
        if checkpoint_path is not None:
            deduper.save_state(checkpoint_path)
    return rows


def run_all(input_dir: str = RAW_DATA, limit: int | None = None,
            resume: bool = True) -> list[dict]:
    """Full pipeline (legacy global pass). `limit` caps records per file.

    `resume=True` (default) reloads the dedup checkpoint if one exists, so an
    interrupted run can continue without re-processing previously seen hashes.
    """
    deduper = Deduper()
    if resume:
        deduper.load_state(DEDUP_CKPT)
    redactor = Redactor()
    langf = LangFilter()
    translator = Translator()
    logger.info(f"cleaning input: {input_dir}")
    logger.info(f"backends -> dedup:{deduper.backend} pii:{redactor.engine} "
                f"lang:{langf.backend} translate:{translator.backend}")

    files = list(find_input_files(input_dir))
    if not files:
        logger.warning(f"no .jsonl files under {input_dir} "
                       "(run the extraction stage first)")
        return []

    rows = clean_files(files, deduper=deduper, redactor=redactor, langf=langf,
                       translator=translator, out_cleaned=OUT_CLEAN_DATA,
                       out_flagged=OUT_FLAGGED, out_dropped=OUT_DROPPED,
                       limit=limit, checkpoint_path=DEDUP_CKPT)
    _write_report(rows)
    return rows


def clean_one_source(source_dir: str, *, raw_root: str = RAW_DATA,
                     clean_data_dir: str = OUT_CLEAN_DATA,
                     limit: int | None = None) -> list[dict]:
    """Clean a single source's .jsonl files into `data/clean/` (no global dedup).

    Used by the parallel per-source worker. Global cross-source dedup is deferred
    to `final_global_dedup`; here the deduper is disabled so each worker stays
    isolated. Output mirrors the data/raw layout (rel paths are relative to
    `raw_root`). Returns report rows for the parent to aggregate.
    """
    source_dir = os.path.abspath(source_dir)
    files = [t for t in find_input_files(raw_root)
             if os.path.abspath(t[0]).startswith(source_dir + os.sep)
             or os.path.abspath(t[0]) == source_dir]
    if not files:
        return []
    deduper = Deduper(enabled=False)
    redactor = Redactor()
    langf = LangFilter()
    translator = Translator()
    return clean_files(files, deduper=deduper, redactor=redactor, langf=langf,
                       translator=translator, out_cleaned=clean_data_dir,
                       out_flagged=OUT_FLAGGED, out_dropped=OUT_DROPPED,
                       limit=limit)


def final_global_dedup(clean_data_dir: str = OUT_CLEAN_DATA) -> dict:
    """One cross-source dedup pass over `data/clean/`, rewriting files in place.

    The per-source workers skip global dedup, so this single pass (run once in
    the parent after the pool drains) is what catches duplicates shared across
    sources. Removed records are appended to `dropped/` with a `dedup` reason.
    """
    deduper = Deduper()
    stats = {"files": 0, "in": 0, "kept": 0, "exact_dups": 0, "near_dups": 0}
    logger.info(f"final global dedup over {clean_data_dir} "
                f"(backend={deduper.backend})")
    for ap, sub, source, rel in find_input_files(clean_data_dir):
        stats["files"] += 1
        # Append (don't truncate): the per-source clean already wrote structural
        # / language drops to dropped/<rel>; cross-source dups go to the same file.
        dropped_path = os.path.join(OUT_DROPPED, rel)
        dropped_fh = None
        fd, tmp = tempfile.mkstemp(suffix=".jsonl", dir=os.path.dirname(ap))
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
                        dropped_fh.write(json.dumps(
                            _annotate(rec, sub, source, rel, "dedup", dreason),
                            ensure_ascii=False) + "\n")
                        continue
                    out.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    stats["kept"] += 1
        finally:
            if dropped_fh is not None:
                dropped_fh.close()
        os.replace(tmp, ap)
    logger.info("final dedup: files={files} in={in} kept={kept} "
                "exact_dups={exact_dups} near_dups={near_dups}".format(**stats))
    return stats


def _write_report(rows: list[dict]) -> str:
    os.makedirs(REPORTS, exist_ok=True)
    path = os.path.join(REPORTS, "clean_report.csv")
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

    Not the production path (use run_all); a debugging aid for one transform.
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
