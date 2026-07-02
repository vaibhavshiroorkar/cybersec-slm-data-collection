#!/usr/bin/env python3
"""Unified command-line entry point for the pipeline.

Full pipeline (end-to-end):
    cybersec-slm all

Individual stages:
    cybersec-slm run      [--sources X.csv] [--workers N] [--resume]  # streaming fetch+clean
    cybersec-slm clean    [sanitize|dedup|pii|lang|report|balance]   # diagnostics/ops
    cybersec-slm normalize | eda | validate
    cybersec-slm source   [--domains ...] [--dry-run]        # search engines -> Sources.csv
    cybersec-slm dashboard [--port N]                        # Streamlit monitor + explorer

Ingestion reads sources/Sources.csv. NVD needs no flag — set NVD_API_KEY (env) to
raise its rate limit.
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

    # ── clean (diagnostics / ops) ─────────────────────────────────────────────
    c = sub.add_parser("clean",
                       help="cleaning diagnostics/ops (single-stage, report, balance)")
    c.add_argument("action",
                   choices=["sanitize", "dedup", "pii", "lang", "report", "balance"],
                   help="sanitize|dedup|pii|lang: run one transform -> data/_stages/ "
                        "for inspection; report: recount output trees; "
                        "balance: per-domain record counts")
    c.add_argument("--limit", type=int, default=None,
                   help="cap records per file (smoke test)")
    c.add_argument("--cap", type=int, default=None,
                   help="max records per domain (balance action)")

    # ── normalize ─────────────────────────────────────────────────────────────
    n = sub.add_parser("normalize",
                       help="schema-normalize data/clean/ -> data/final/dataset.jsonl")
    n.add_argument("--input", default=None,
                   help="cleaned-records root (default: data/clean/)")
    n.add_argument("--fresh", action="store_true",
                   help="ignore any existing dataset.jsonl (do not resume/append)")
    n.add_argument("--limit", type=int, default=None,
                   help="cap records per file (smoke test)")

    # ── eda ───────────────────────────────────────────────────────────────────
    ed = sub.add_parser("eda",
                        help="validate cleaned corpus + sufficiency gate (-> logs/eda/)")
    ed.add_argument("--input", default=None,
                    help="cleaned-records root (default: data/clean/)")
    ed.add_argument("--no-enforce", action="store_true",
                    help="report only; do not fail the run on a blocker")
    ed.add_argument("--profile", action="store_true",
                    help="also write a ydata-profiling HTML report (needs ydata-profiling, "
                         "which requires pandas<3 — run it in a throwaway env; see README)")

    # ── validate ──────────────────────────────────────────────────────────────
    sub.add_parser("validate",
                   help="validate data/clean/ records against Pydantic schema")

    # ── run (parallel streaming) ──────────────────────────────────────────────
    r = sub.add_parser("run",
                       help="parallel per-source fetch+clean -> data/clean/")
    r.add_argument("--sources", default=None,
                   help="path to a sources .csv (default: sources/Sources.csv)")
    r.add_argument("--workers", type=int, default=None,
                   help="process pool size (default: min(cpu, 8))")
    r.add_argument("--limit", type=int, default=None,
                   help="cap records per file (smoke test)")
    r.add_argument("--keep-raw", action="store_true",
                   help="keep data/raw/ instead of deleting after clean")
    r.add_argument("--no-final-dedup", action="store_true",
                   help="skip the final cross-source dedup pass")
    r.add_argument("--resume", action="store_true",
                   help="skip sources already fetched+cleaned in a prior run "
                        "(logs/completed_sources.txt) and resume the final dedup")

    # ── source (search-engine source discovery) ─────────────────────────────
    d = sub.add_parser("source",
                       help="search engines by keyword -> append new rows to Sources.csv")
    d.add_argument("--sources", default=None,
                   help="catalog CSV to append to (default: sources/Sources.csv)")
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
                   help="discover + write CSV but do not append to Sources.csv")
    d.add_argument("--out", default=None,
                   help="path for the candidate CSV (default: logs/discovered/)")
    d.add_argument("--api-key", default=None,
                   help="Google API key (env: GOOGLE_SEARCH_API_KEY)")
    d.add_argument("--cse-id", default=None,
                   help="Programmable Search id (env: GOOGLE_SEARCH_ENGINE_ID)")

    # ── flow (Prefect orchestration) ──────────────────────────────────────────
    fl = sub.add_parser("flow",
                        help="run the Prefect build-corpus flow (needs orchestration extra)")
    fl.add_argument("--sources", default=None, help="path to a sources .csv")
    fl.add_argument("--no-enforce-eda", action="store_true",
                    help="run the EDA gate in report-only mode")
    fl.add_argument("--dvc-push", action="store_true",
                    help="snapshot + push the dataset to the DVC remote")

    # ── dashboard (Streamlit monitor + explorer) ──────────────────────────────
    db = sub.add_parser("dashboard",
                        help="launch the read-only monitor + dataset explorer "
                             "(needs the dashboard extra)")
    db.add_argument("--port", type=int, default=8501,
                    help="Streamlit server port (default 8501)")
    db.add_argument("--headless", action="store_true",
                    help="run headless (don't auto-open a browser; for remote use)")

    # ── all ───────────────────────────────────────────────────────────────────
    a = sub.add_parser("all", help="ingest -> clean -> normalize (full pipeline)")
    a.add_argument("--resume", action="store_true",
                   help="skip sources already fetched+cleaned in a prior run "
                        "(logs/completed_sources.txt) and resume the final dedup")
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)

    if args.stage == "clean":
        from .cleaning import run as cleaning
        if args.action == "balance":
            from .cleaning.balance import apply_cap, check_balance
            check_balance()
            if args.cap:
                apply_cap(args.cap)
        else:
            cleaning.run(args.action, limit=args.limit)

    elif args.stage == "run":
        from .ingestion import parallel
        parallel.run_streaming(args.sources,
                               workers=args.workers, limit=args.limit,
                               keep_raw=args.keep_raw,
                               final_dedup=not args.no_final_dedup,
                               resume=args.resume)

    elif args.stage == "normalize":
        from .normalize import run_normalization
        run_normalization(args.input, resume=not args.fresh, limit=args.limit)

    elif args.stage == "eda":
        from .eda import run_eda
        run_eda(args.input, enforce=not args.no_enforce, profile=args.profile)

    elif args.stage == "flow":
        from .orchestration.flows import build_corpus
        build_corpus(args.sources, enforce_eda=not args.no_enforce_eda,
                     dvc_push=args.dvc_push)

    elif args.stage == "validate":
        from .cleaning.schema import validate_corpus
        validate_corpus()

    elif args.stage == "dashboard":
        from .dashboard.launch import launch
        launch(port=args.port, headless=args.headless)

    elif args.stage == "source":
        from .sourcing import run as sourcing
        summary = sourcing.discover(
            args.sources, domains=args.domains,
            per_keyword=args.per_keyword, max_per_domain=args.max_per_domain,
            mode=args.mode, dry_run=args.dry_run, out_csv=args.out,
            api_key=(args.api_key or os.environ.get("GOOGLE_SEARCH_API_KEY")
                     or os.environ.get("GOOGLE_API_KEY")),
            cse_id=(args.cse_id or os.environ.get("GOOGLE_SEARCH_ENGINE_ID")
                    or os.environ.get("GOOGLE_CSE_ID")))
        print(f"source: {summary['found']} hits, {summary['new']} new, "
              f"{summary['appended']} appended -> {summary['csv']}")

    elif args.stage == "all":
        from .core import logger
        from .eda import SufficiencyError, run_eda
        from .ingestion import parallel
        from .normalize import run_normalization
        # Streaming ingestion from sources/Sources.csv: fetch + clean fused per
        # source, then one final cross-source dedup pass (no separate clean stage).
        parallel.run_streaming(resume=args.resume)
        # EDA sufficiency gate: a blocker means loop back to ingestion, not advance.
        try:
            run_eda(enforce=True)
        except SufficiencyError as exc:
            logger.error(str(exc))
            print("Pipeline halted at the EDA sufficiency gate — "
                  "address the blockers above and re-run.")
            return
        # full rebuild: ingestion regenerates data/clean/ upstream, so normalize
        # fresh (resume=False) instead of appending/deduping against a stale dataset.
        run_normalization(resume=False)


if __name__ == "__main__":
    main()
