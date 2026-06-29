#!/usr/bin/env python3
"""Run individual cleaning stages with outputs organized by domain in cleaned_data/"""

import os
import sys
import json
from pathlib import Path
from typing import Optional

from cybersec_slm.cleaning.common import find_input_files, iter_jsonl, logger, LOGS
from cybersec_slm.cleaning import sanitize, anomaly, dedup, pii, langfilter
from cybersec_slm.core import JsonlWriter, PARSE_ERROR

# Output structure: cleaned_data/<domain>/<stage>/
CLEANED_DATA_ROOT = os.path.join(os.getcwd(), "cleaned_data")


def get_output_paths(domain: str, stage: str):
    """Get output directory paths for a domain and stage."""
    domain_dir = os.path.join(CLEANED_DATA_ROOT, domain)
    stage_dir = os.path.join(domain_dir, stage)
    os.makedirs(stage_dir, exist_ok=True)
    return domain_dir, stage_dir


def run_stage_by_domain(stage: str, domain: Optional[str] = None, limit: int | None = None):
    """Run a single stage for specific domain or all domains.
    
    Args:
        stage: 'sanitize', 'dedup', 'pii', or 'lang'
        domain: Run only this domain, or None for all
        limit: Cap records per file (for testing)
    """
    print(f"\n{'='*70}")
    print(f"Stage: {stage.upper()}")
    print(f"Domain: {domain or 'ALL'}")
    print(f"{'='*70}\n")
    
    # Get input files
    files = list(find_input_files())
    if not files:
        logger.warning("No .jsonl files found under raw_data/")
        return
    
    # Filter by domain if specified
    if domain:
        files = [(ap, sd, src, rel) for ap, sd, src, rel in files if sd == domain]
    
    # Initialize stage processors
    if stage == "sanitize":
        processor = _make_sanitize_processor()
    elif stage == "dedup":
        deduper = dedup.Deduper()
        processor = _make_dedup_processor(deduper)
    elif stage == "pii":
        redactor = pii.Redactor()
        processor = _make_pii_processor(redactor)
    elif stage == "lang":
        langf = langfilter.LangFilter()
        processor = _make_lang_processor(langf)
    else:
        raise ValueError(f"Unknown stage: {stage}")
    
    # Process each file
    total_in = 0
    total_out = 0
    
    for ap, sub_domain, source, rel in files:
        domain_dir, stage_dir = get_output_paths(sub_domain, stage)
        out_path = os.path.join(stage_dir, rel)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        
        out_writer = JsonlWriter(out_path)
        
        with open(ap, 'r', encoding='utf-8', errors='replace') as f:
            for i, line in enumerate(f):
                if limit is not None and i >= limit:
                    break
                try:
                    rec = json.loads(line)
                    total_in += 1
                    result = processor(rec)
                    if result is not None:
                        out_writer.write(result)
                        total_out += 1
                except json.JSONDecodeError as e:
                    logger.debug(f"JSON decode error in {rel}: {e}")
                    continue
        
        logger.info(f"  {sub_domain}: {rel} -> in={i+1 if i+1 > 0 else 0} out={(total_out - (total_in - i - 1)) if i+1 > 0 else 0}")
    
    logger.info(f"\nStage '{stage}' complete: in={total_in} out={total_out}")
    print(f"\n✓ Output: {CLEANED_DATA_ROOT}/<domain>/{stage}/\n")


def _make_sanitize_processor():
    """Return a processor function for sanitize stage."""
    def process(rec):
        if rec.get(PARSE_ERROR):
            return None
        rec2, _ = sanitize.sanitize_record(rec)
        return rec2
    return process


def _make_dedup_processor(deduper):
    """Return a processor function for dedup stage."""
    def process(rec):
        return rec if not deduper.is_dup(rec) else None
    return process


def _make_pii_processor(redactor):
    """Return a processor function for PII stage."""
    def process(rec):
        return redactor.anonymize_record(rec)
    return process


def _make_lang_processor(langf):
    """Return a processor function for language filter stage."""
    def process(rec):
        from cybersec_slm.cleaning.common import text_of
        text = text_of(rec)
        if langf.is_english(text):
            return rec
        return None
    return process


def list_domains():
    """List all available domains in raw_data/."""
    files = list(find_input_files())
    domains = sorted(set(sd for _, sd, _, _ in files))
    return domains


def main():
    if len(sys.argv) < 2:
        print("""Usage: python run_individual_stages_by_domain.py <command> [options]

Commands:
  list-domains              List all available domains
  sanitize [domain]         Run sanitize stage (optionally for specific domain)
  dedup [domain]            Run dedup stage
  pii [domain]              Run PII stage
  lang [domain]             Run language filter stage
  all [domain]              Run all stages sequentially
  
Options:
  --limit N                 Cap records per file (for testing)

Examples:
  python run_individual_stages_by_domain.py list-domains
  python run_individual_stages_by_domain.py sanitize
  python run_individual_stages_by_domain.py sanitize "Security Operations"
  python run_individual_stages_by_domain.py all "Threat Intelligence" --limit 50
        """)
        sys.exit(1)
    
    cmd = sys.argv[1]
    domain = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else None
    limit = None
    if "--limit" in sys.argv:
        idx = sys.argv.index("--limit")
        if idx + 1 < len(sys.argv):
            limit = int(sys.argv[idx + 1])
    
    if cmd == "list-domains":
        domains = list_domains()
        print(f"\nAvailable domains ({len(domains)}):")
        for d in domains:
            print(f"  - {d}")
        print()
    elif cmd == "all":
        for stage in ["sanitize", "dedup", "pii", "lang"]:
            run_stage_by_domain(stage, domain, limit)
    elif cmd in ["sanitize", "dedup", "pii", "lang"]:
        run_stage_by_domain(cmd, domain, limit)
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
