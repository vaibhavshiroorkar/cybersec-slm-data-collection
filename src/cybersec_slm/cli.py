#!/usr/bin/env python3
"""Unified command-line entry point for the pipeline.

Full pipeline (end-to-end):
    cybersec-slm all      # ingest -> clean -> EDA -> schema (five stages)

Individual stages:
    cybersec-slm source   [--domains ...] [--dry-run]        # 1: search -> Sources.csv
    cybersec-slm ingest   [--sources X.csv] [--workers N] [--resume]  # 2: fetch -> data/raw/
    cybersec-slm clean    [--purge-raw] [--resume]           # 3: clean + dedup -> data/clean/
    cybersec-slm eda      [--no-enforce]                     # 4: sufficiency gate
    cybersec-slm schema   (alias of normalize)               # 5: -> data/final/dataset.jsonl
    cybersec-slm clean    [sanitize|dedup|pii|lang|report|balance]   # clean diagnostics/ops
    cybersec-slm validate
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

    # ── clean (stage 3) + diagnostics / ops ───────────────────────────────────
    c = sub.add_parser("clean",
                       help="clean data/raw/ -> data/clean/ + cross-source dedup "
                            "(stage 3); or a single-stage diagnostic")
    c.add_argument("action", nargs="?", default=None,
                   choices=["sanitize", "dedup", "pii", "lang", "report", "balance"],
                   help="omit to run the full clean stage. sanitize|dedup|pii|lang: "
                        "run one transform -> data/_stages/ for inspection; report: "
                        "recount output trees; balance: per-domain record counts")
    c.add_argument("--purge-raw", action="store_true",
                   help="clean stage: delete data/raw/ after cleaning "
                        "(default: keep it)")
    c.add_argument("--resume", action="store_true",
                   help="clean stage: continue a partial cross-source dedup pass")
    c.add_argument("--drop-non-english", action="store_true",
                   help="drop non-English records instead of translating them")
    c.add_argument("--limit", type=int, default=None,
                   help="cap records per file (smoke test)")
    c.add_argument("--cap", type=int, default=None,
                   help="max records per domain (balance action)")
    c.add_argument("--source-share", type=float, default=None, metavar="SHARE",
                   help="balance action: downsample any single source above SHARE "
                        "(e.g. 0.6) of its subdomain. Opt-in - destroys data when "
                        "secondary sources are small; prefer adding sources.")

    # ── normalize / schema (stage 5) ──────────────────────────────────────────
    n = sub.add_parser("normalize", aliases=["schema"],
                       help="schema-normalize data/clean/ -> data/final/dataset.jsonl "
                            "(stage 5)")
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
    ed.add_argument("--no-auto-rebalance", action="store_true",
                    help="disable automatic rebalancing of over-represented subdomains")
    ed.add_argument("--profile", action="store_true",
                    help="also write a ydata-profiling HTML report (needs ydata-profiling, "
                         "which requires pandas<3 — run it in a throwaway env; see README)")

    # ── validate ──────────────────────────────────────────────────────────────
    sub.add_parser("validate",
                   help="validate data/clean/ records against Pydantic schema")

    # ── ingest (stage 2: fetch-only) ──────────────────────────────────────────
    ig = sub.add_parser("ingest",
                        help="fetch all sources -> data/raw/ (stage 2; no cleaning)")
    ig.add_argument("--sources", default=None,
                    help="path to a sources .csv (default: sources/Sources.csv)")
    ig.add_argument("--workers", type=int, default=None,
                    help="process pool size (default: min(cpu, 8))")
    ig.add_argument("--limit", type=int, default=None,
                    help="cap records per file (smoke test)")
    ig.add_argument("--resume", action="store_true",
                    help="skip sources already fetched in a prior run "
                         "(logs/completed_sources.txt)")
    ig.add_argument("--max-source-gb", type=float, default=None,
                    help="skip sources larger than this many GB (catalog size)")
    ig.add_argument("--source-timeout", type=float, default=1800.0,
                    help="per-source wall-clock timeout in seconds "
                         "(abandon a hung source; default 1800)")

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

    # ── synthetic-scan (curation aid) ─────────────────────────────────────────
    ss = sub.add_parser("synthetic-scan",
                        help="suggest which sources look synthetic (keyword scan "
                             "of Sources.csv); propose-only unless --apply")
    ss.add_argument("--sources", default=None,
                    help="catalog CSV to scan (default: sources/Sources.csv)")
    ss.add_argument("--apply", action="store_true",
                    help="write Is Synthetic?=Yes for high-confidence gaps "
                         "(review-level matches are never auto-applied)")

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
    a = sub.add_parser("all",
                       help="full pipeline: ingest -> clean -> EDA -> schema (5 stages)")
    a.add_argument("--sources", default=None,
                   help="path to a sources .csv (default: sources/Sources.csv)")
    a.add_argument("--workers", type=int, default=None,
                   help="ingest process pool size (default: min(cpu, 8))")
    a.add_argument("--resume", action="store_true",
                   help="skip sources already fetched in a prior run "
                        "(logs/completed_sources.txt)")
    a.add_argument("--purge-raw", action="store_true",
                   help="delete data/raw/ after cleaning (default: keep it)")
    a.add_argument("--limit", type=int, default=None,
                   help="cap records per file (smoke test)")
    a.add_argument("--no-auto-rebalance", action="store_true",
                   help="disable automatic rebalancing of over-represented subdomains")
    a.add_argument("--max-source-gb", type=float, default=None,
                   help="skip sources larger than this many GB (catalog size)")
    a.add_argument("--drop-non-english", action="store_true",
                   help="drop non-English records instead of translating them")
    a.add_argument("--source-timeout", type=float, default=1800.0,
                   help="per-source wall-clock timeout in seconds "
                        "(abandon a hung source; default 1800)")
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)

    if args.stage == "clean":
        if args.action is None:
            # Stage 3: clean the whole raw tree + cross-source dedup.
            from .ingestion import parallel
            parallel.run_clean(keep_raw=not args.purge_raw, limit=args.limit,
                               resume=args.resume,
                               drop_non_english=args.drop_non_english)
        elif args.action == "balance":
            from .cleaning.balance import apply_cap, apply_source_cap, check_balance
            check_balance()
            if args.cap:
                apply_cap(args.cap)
            if args.source_share is not None:
                apply_source_cap(args.source_share)
        else:
            from .cleaning import run as cleaning
            cleaning.run(args.action, limit=args.limit)

    elif args.stage == "ingest":
        # Stage 2: fetch every source to data/raw/ (no cleaning).
        from .ingestion import parallel
        parallel.run_ingest(args.sources,
                            workers=args.workers,
                            resume=args.resume,
                            limit=args.limit,
                            source_timeout=args.source_timeout,
                            max_source_gb=args.max_source_gb)

    elif args.stage in ("normalize", "schema"):
        from .normalize import run_normalization
        run_normalization(args.input, resume=not args.fresh, limit=args.limit)

    elif args.stage == "eda":
        # Disable auto-rebalance if requested
        if getattr(args, "no_auto_rebalance", False):
            from .eda import config as eda_config
            eda_config.AUTO_REBALANCE = False
        from .eda import run_eda
        run_eda(args.input, enforce=not args.no_enforce, profile=args.profile)

    elif args.stage == "flow":
        from .orchestration.flows import build_corpus
        build_corpus(args.sources, enforce_eda=not args.no_enforce_eda,
                     dvc_push=args.dvc_push)

    elif args.stage == "validate":
        from .cleaning.schema import validate_corpus
        validate_corpus()

    elif args.stage == "synthetic-scan":
        from .sourcing.synthetic_scan import run_scan
        run_scan(args.sources, apply=args.apply)

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
        # Full pipeline: ingest -> clean -> EDA -> schema (five stages, no overlap).
        if getattr(args, "no_auto_rebalance", False):
            from .eda import config as eda_config
            eda_config.AUTO_REBALANCE = False
        from .ingestion import parallel
        parallel.run_v2_pipeline(
            args.sources,
            workers=args.workers,
            resume=args.resume,
            keep_raw=not args.purge_raw,
            limit=getattr(args, "limit", None),
            source_timeout=args.source_timeout,
            max_source_gb=args.max_source_gb,
            drop_non_english=args.drop_non_english,
        )


if __name__ == "__main__":
    main()
