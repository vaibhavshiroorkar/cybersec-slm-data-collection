#!/usr/bin/env python3
"""Unified command-line entry point for the pipeline.

Full pipeline (end-to-end):
    cybersec-slm all

Individual stages:
    cybersec-slm extract  [scrape|fetch|html|nvd|all|table] [--nvd-key KEY]
    cybersec-slm clean    [all|sanitize|dedup|pii|lang|report|balance] [--limit N] [--cap N]
    cybersec-slm run      [--sources X.xlsx] [--workers N]   # parallel streaming fetch+clean
    cybersec-slm validate
    cybersec-slm discover [--domains ...] [--dry-run]        # search engines -> tracking sheet
"""

from __future__ import annotations

import argparse
import os


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cybersec-slm",
        description="Cybersecurity SLM data pipeline.",
    )
    sub = p.add_subparsers(dest="stage", required=True)

    # ── extract ──────────────────────────────────────────────────────────────
    e = sub.add_parser("extract", help="pull + normalise sources -> raw_data/")
    e.add_argument("action", nargs="?", default="all",
                   choices=["scrape", "fetch", "html", "nvd", "all", "table"])
    e.add_argument("--nvd-key", default=None,
                   help="NVD API key (env: NVD_API_KEY). Higher rate-limit.")

    # ── clean ─────────────────────────────────────────────────────────────────
    c = sub.add_parser("clean", help="clean raw_data/ -> cleaned/")
    c.add_argument("action", nargs="?", default="all",
                   choices=["all", "sanitize", "dedup", "pii", "lang",
                            "report", "balance"])
    c.add_argument("--limit", type=int, default=None,
                   help="cap records per file (smoke test)")
    c.add_argument("--cap", type=int, default=None,
                   help="max records per domain (balance action)")

    # ── validate ──────────────────────────────────────────────────────────────
    sub.add_parser("validate",
                   help="validate cleaned/ records against Pydantic schema")

    # ── run (parallel streaming) ──────────────────────────────────────────────
    r = sub.add_parser("run",
                       help="parallel per-source fetch+clean -> clean_data/")
    r.add_argument("--sources", default=None,
                   help="path or URL to a sources .xlsx (default: manifest.py)")
    r.add_argument("--sheet", default=None, help="worksheet name/index")
    r.add_argument("--workers", type=int, default=None,
                   help="process pool size (default: min(cpu, 8))")
    r.add_argument("--limit", type=int, default=None,
                   help="cap records per file (smoke test)")
    r.add_argument("--keep-raw", action="store_true",
                   help="keep raw_data/ instead of deleting after clean")
    r.add_argument("--no-final-dedup", action="store_true",
                   help="skip the final cross-source dedup pass")

    # ── discover (search-engine source discovery) ────────────────────────────
    d = sub.add_parser("discover",
                       help="search engines by keyword -> append new rows to the sheet")
    d.add_argument("--sheet-url", default=None,
                   help="tracking sheet URL/id (default: the finalized sheet)")
    d.add_argument("--domains", nargs="*", default=None,
                   help="limit to these Sub-Domains (default: all)")
    d.add_argument("--mode", choices=["datasets", "text", "both"], default="datasets",
                   help="keyword catalog: datasets (corpora/repos), text "
                        "(articles/docs), or both (default: datasets)")
    d.add_argument("--per-keyword", type=int, default=5,
                   help="results to request per keyword (<=10, default 5)")
    d.add_argument("--max-per-domain", type=int, default=None,
                   help="cap new rows kept per Sub-Domain")
    d.add_argument("--dry-run", action="store_true",
                   help="discover + write CSV but do not append to the sheet")
    d.add_argument("--out", default=None,
                   help="path for the candidate CSV (default: logs/discovered/)")
    d.add_argument("--api-key", default=None,
                   help="Google API key (env: GOOGLE_SEARCH_API_KEY)")
    d.add_argument("--cse-id", default=None,
                   help="Programmable Search id (env: GOOGLE_SEARCH_ENGINE_ID)")
    d.add_argument("--creds", default=None,
                   help="service-account JSON for append (env: GOOGLE_SHEETS_CREDENTIALS)")

    # ── all ───────────────────────────────────────────────────────────────────
    sub.add_parser("all", help="extract -> clean (full pipeline)")
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)

    if args.stage == "extract":
        from .extraction import run as extraction
        extraction.run(args.action,
                       nvd_key=args.nvd_key or os.environ.get("NVD_API_KEY"))

    elif args.stage == "clean":
        from .cleaning import run as cleaning
        if args.action == "balance":
            from .cleaning.balance import apply_cap, check_balance
            check_balance()
            if args.cap:
                apply_cap(args.cap)
        else:
            cleaning.run(args.action, limit=args.limit)

    elif args.stage == "run":
        from .extraction import parallel
        parallel.run_streaming(args.sources, sheet=args.sheet,
                               workers=args.workers, limit=args.limit,
                               keep_raw=args.keep_raw,
                               final_dedup=not args.no_final_dedup)

    elif args.stage == "validate":
        from .cleaning.schema import validate_corpus
        validate_corpus()

    elif args.stage == "discover":
        from .discovery import run as discovery
        summary = discovery.discover(
            args.sheet_url, domains=args.domains,
            per_keyword=args.per_keyword, max_per_domain=args.max_per_domain,
            mode=args.mode, dry_run=args.dry_run, out_csv=args.out,
            api_key=(args.api_key or os.environ.get("GOOGLE_SEARCH_API_KEY")
                     or os.environ.get("GOOGLE_API_KEY")),
            cse_id=(args.cse_id or os.environ.get("GOOGLE_SEARCH_ENGINE_ID")
                    or os.environ.get("GOOGLE_CSE_ID")),
            creds_path=args.creds or os.environ.get("GOOGLE_SHEETS_CREDENTIALS"))
        print(f"discover: {summary['found']} hits, {summary['new']} new, "
              f"{summary['appended']} appended -> {summary['csv']}")

    elif args.stage == "all":
        from .extraction import run as extraction
        from .cleaning import run as cleaning
        extraction.run("all")
        cleaning.run("all")


if __name__ == "__main__":
    main()
