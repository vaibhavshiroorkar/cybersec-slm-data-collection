#!/usr/bin/env python3
"""Clean datasets by domain using individual stages. Method 2 optimized.

Stages are CHAINED: each stage reads from the previous stage's output.

  raw_data/ → sanitize → dedup → pii → lang → cleaned_data/<domain>/final/

Intermediate outputs:
  cleaned_data/
    ├── Security Operations/
    │   ├── sanitize/   ← output of sanitize (input to dedup)
    │   ├── dedup/      ← output of dedup    (input to pii)
    │   ├── pii/        ← output of pii      (input to lang)
    │   ├── lang/       ← output of lang     (final cleaned output)
    └── Threat Intelligence/
        ├── sanitize/
        ├── dedup/
        ├── pii/
        └── lang/
"""

import os
import sys
import json
from pathlib import Path

from cybersec_slm.cleaning.common import find_input_files, iter_jsonl, logger, text_of, PARSE_ERROR
from cybersec_slm.cleaning import sanitize, anomaly, dedup, pii, langfilter
from cybersec_slm.core import JsonlWriter

CLEANED_DATA_ROOT = os.path.join(os.getcwd(), "cleaned_data")
RAW_DATA_ROOT = os.path.join(os.getcwd(), "raw_data")

# Stage order — each reads from the previous
STAGE_ORDER = ["sanitize", "dedup", "pii", "lang"]


def get_stage_dir(domain: str, stage: str) -> str:
    """Get output directory for domain+stage, create if needed."""
    out_dir = os.path.join(CLEANED_DATA_ROOT, domain, stage)
    os.makedirs(out_dir, exist_ok=True)
    return out_dir


def get_input_dir_for_stage(domain: str, stage: str) -> str:
    """
    Return the directory to READ FROM for a given stage.
    - sanitize reads from raw_data/
    - all subsequent stages read from the previous stage's output
    """
    if stage == "sanitize":
        # Walk raw_data to find files for this domain
        return None  # handled separately via find_input_files()
    else:
        prev_stage = STAGE_ORDER[STAGE_ORDER.index(stage) - 1]
        return os.path.join(CLEANED_DATA_ROOT, domain, prev_stage)


def find_chained_files(domain: str, stage: str):
    """
    Yield (absolute_path, filename) for the input files of a given stage.
    - sanitize: reads from raw_data/ via find_input_files()
    - others: reads from previous stage's output dir
    """
    if stage == "sanitize":
        all_files = list(find_input_files())
        for ap, sd, src, rel in all_files:
            if sd == domain:
                yield ap, os.path.basename(ap)
    else:
        input_dir = get_input_dir_for_stage(domain, stage)
        if not os.path.isdir(input_dir):
            logger.warning(f"  Input dir not found for stage '{stage}': {input_dir}")
            logger.warning(f"  → Did you run the '{STAGE_ORDER[STAGE_ORDER.index(stage)-1]}' stage first?")
            return
        for fn in sorted(os.listdir(input_dir)):
            if fn.endswith(".jsonl"):
                yield os.path.join(input_dir, fn), fn


def make_processor(stage: str):
    """Return a stateful processor function for the given stage."""
    if stage == "sanitize":
        def processor(rec):
            if rec.get(PARSE_ERROR):
                return None
            rec2, _ = sanitize.sanitize_record(rec)
            return rec2

    elif stage == "dedup":
        deduper = dedup.Deduper()
        def processor(rec):
            t = text_of(rec)
            is_dup, _ = deduper.add(t)
            return None if is_dup else rec

    elif stage == "pii":
        redactor = pii.Redactor()
        def processor(rec):
            for field in ("description", "raw_log", "additional_info", "text", "content", "message", "body"):
                if rec.get(field) and isinstance(rec[field], str):
                    new_text, npii = redactor.redact(rec[field])
                    if npii:
                        rec[field] = new_text
            return rec

    elif stage == "lang":
        langf = langfilter.LangFilter()
        def processor(rec):
            t = text_of(rec)
            return rec if langf.is_allowed(t) else None

    else:
        raise ValueError(f"Unknown stage: {stage}")

    return processor


def process_stage(stage: str, domain: str | None = None, limit: int | None = None):
    """
    Process one stage for one or all domains.
    Reads from previous stage output (or raw_data for sanitize).
    """
    # Determine which domains to process
    if domain:
        domains = [domain]
    else:
        all_files = list(find_input_files())
        domains = sorted(set(sd for _, sd, _, _ in all_files))

    if not domains:
        logger.warning("No domains found.")
        return

    print(f"\n{'='*70}")
    print(f"Stage: {stage.upper()}")
    if domain:
        print(f"Domain: {domain}")
    else:
        print(f"Domains: {', '.join(domains)}")
    prev = STAGE_ORDER[STAGE_ORDER.index(stage) - 1] if stage != "sanitize" else "raw_data"
    print(f"Reading from: {prev}/")
    print(f"Writing to:   cleaned_data/<domain>/{stage}/")
    print(f"{'='*70}\n")

    total_stats = {d: {"in": 0, "out": 0} for d in domains}

    for d in domains:
        # One processor instance per domain (keeps dedup state per domain)
        processor = make_processor(stage)
        out_dir = get_stage_dir(d, stage)

        files = list(find_chained_files(d, stage))
        if not files:
            logger.warning(f"  No input files found for domain '{d}' stage '{stage}'")
            continue

        for ap, filename in files:
            try:
                in_count = 0
                out_count = 0
                out_file = os.path.join(out_dir, filename)
                out_writer = JsonlWriter(out_file)

                with open(ap, 'r', encoding='utf-8', errors='replace') as f:
                    for line in f:
                        if limit and in_count >= limit:
                            break
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                            in_count += 1
                            result = processor(rec)
                            if result is not None:
                                out_writer.write(result)
                                out_count += 1
                        except json.JSONDecodeError:
                            continue

                total_stats[d]["in"] += in_count
                total_stats[d]["out"] += out_count

                drop_pct = 100 * (in_count - out_count) / in_count if in_count else 0
                logger.info(
                    f"  {d:25} | {filename:40} | "
                    f"in={in_count:6} out={out_count:6} dropped={in_count-out_count:6} ({drop_pct:5.1f}%)"
                )

            except Exception as e:
                logger.error(f"  Error processing {ap}: {e}")

    # Summary
    print()
    for d in sorted(total_stats.keys()):
        stats = total_stats[d]
        if stats["in"] > 0:
            pct = 100 * stats["out"] / stats["in"]
            dropped = stats["in"] - stats["out"]
            logger.info(
                f"  {d:25} | Total in={stats['in']:7} out={stats['out']:7} "
                f"dropped={dropped:7} ({pct:5.1f}% kept)"
            )

    print(f"\n✓ Stage '{stage}' complete → {CLEANED_DATA_ROOT}/<domain>/{stage}/\n")


def run_all_stages(domain: str | None = None, limit: int | None = None):
    """Run all stages sequentially with proper chaining."""
    print(f"\n{'#'*70}")
    print(f"  Running full pipeline: {' → '.join(STAGE_ORDER)}")
    if domain:
        print(f"  Domain: {domain}")
    if limit:
        print(f"  Limit: {limit} records per file")
    print(f"{'#'*70}")

    for stage in STAGE_ORDER:
        process_stage(stage, domain, limit)

    print(f"\n{'#'*70}")
    print(f"  Pipeline complete.")
    print(f"  Final output: {CLEANED_DATA_ROOT}/<domain>/lang/")
    print(f"{'#'*70}\n")


def list_domains():
    """List all available domains."""
    files = list(find_input_files())
    return sorted(set(sd for _, sd, _, _ in files))


def main():
    if len(sys.argv) < 2:
        print("""
Clean datasets using individual stages with proper chaining.
Each stage reads from the previous stage's output.

Flow: raw_data → sanitize → dedup → pii → lang → cleaned_data/<domain>/lang/

Usage:
  python clean_by_domain.py <command> [domain] [--limit N]

Commands:
  list              List available domains
  sanitize          Run sanitize stage (reads from raw_data/)
  dedup             Run dedup stage    (reads from sanitize/)
  pii               Run PII stage      (reads from dedup/)
  lang              Run lang stage     (reads from pii/)
  all               Run all stages in sequence (sanitize→dedup→pii→lang)

Options:
  [domain]          Process specific domain (optional, default: all)
  --limit N         Cap records per file for testing

Examples:
  python clean_by_domain.py list
  python clean_by_domain.py sanitize "Security Operations"
  python clean_by_domain.py all "Security Operations"
  python clean_by_domain.py all "Threat Intelligence" --limit 100
  python clean_by_domain.py all                         # both domains
        """)
        return

    cmd = sys.argv[1]
    domain = None
    limit = None

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--limit" and i + 1 < len(sys.argv):
            limit = int(sys.argv[i + 1])
            i += 2
        elif not arg.startswith("--") and domain is None:
            domain = arg
            i += 1
        else:
            i += 1

    if cmd == "list":
        domains = list_domains()
        print(f"\nAvailable domains ({len(domains)}):")
        for d in domains:
            print(f"  • {d}")
        print()
    elif cmd == "all":
        run_all_stages(domain, limit)
    elif cmd in STAGE_ORDER:
        process_stage(cmd, domain, limit)
    else:
        print(f"Unknown command: {cmd}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()