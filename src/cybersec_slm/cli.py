#!/usr/bin/env python3
"""Unified command-line entry point for the pipeline.

Full pipeline (end-to-end):
    cybersec-slm all      # ingest -> clean -> EDA -> schema (four stages; run
                          # `source` separately to curate the catalog first)

Individual stages:
    cybersec-slm source   [--domains ...] [--dry-run]        # 1: search -> Sources.csv
    cybersec-slm ingest   [--sources X.csv] [--workers N] [--resume]  # 2: fetch -> data/raw/
    cybersec-slm clean    [--purge-raw] [--resume]           # 3: clean + dedup -> data/clean/
    cybersec-slm eda      [--no-enforce]                     # 4: sufficiency gate
    cybersec-slm schema   (alias of normalize)               # 5: -> data/final/dataset.jsonl
    cybersec-slm clean    [sanitize|dedup|pii|lang|report|balance]   # clean diagnostics/ops
    cybersec-slm validate
    cybersec-slm dashboard [--port N]                        # Streamlit monitor + explorer

Profiles (which corpus every stage works on):
    cybersec-slm profile list | show [NAME] | use NAME | create NAME

Ingestion reads the active profile's Sources.csv. NVD needs no flag — set
NVD_API_KEY (env) to raise its rate limit. Source discovery uses a self-hosted
SearXNG instance — set SEARXNG_URL (env; default http://localhost:8080).
"""

from __future__ import annotations

import argparse
import os


def _physical_cores() -> int:
    """Number of physical CPU cores (not logical/hyperthreads).

    Cleaning is CPU-bound (text normalization, language detection, MinHash), so
    sizing the process pool to physical cores gives the real throughput; the extra
    logical (hyperthread) siblings add little and can hurt via cache/ALU contention.
    Falls back to half the logical count (the common 2-thread-per-core case), then
    to the logical count, when physical detection is unavailable.
    """
    try:
        import psutil
        n = psutil.cpu_count(logical=False)
        if n:
            return int(n)
    except Exception:
        pass
    logical = os.cpu_count() or 1
    return max(1, logical // 2)


# Clean is per-source and embarrassingly parallel (the single cross-source dedup
# pass runs once afterward regardless), so the CLI defaults the clean pool to the
# physical cores. Capped at 8 to bound per-worker memory; pass 1 for sequential.
_DEFAULT_CLEAN_WORKERS = min(_physical_cores(), 8)


def _apply_pii_engine(args) -> None:
    """Publish ``--pii-engine`` to the environment for the clean stage.

    An environment variable rather than a module global on purpose: the clean
    stage runs in *spawned* pool workers, which re-import the cleaning modules
    from scratch and would never observe an assignment made in this process. The
    environment is the one channel that crosses that boundary (children inherit
    it), which is the same mechanism ``CYBERSEC_SLM_PII_MAX_CHARS`` and
    ``CYBERSEC_SLM_TRANSLATE`` already use.
    """
    engine = getattr(args, "pii_engine", None)
    if engine:
        os.environ["CYBERSEC_SLM_PII_ENGINE"] = engine


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
    c.add_argument("--workers", type=int, default=_DEFAULT_CLEAN_WORKERS,
                   help="process pool size for parallel clean workers "
                        "(default: physical cores, max 8; pass 1 to force sequential)")
    c.add_argument("--limit", type=int, default=None,
                   help="cap records per file (smoke test)")
    c.add_argument("--domains", nargs="*", default=None,
                   help="clean only these Sub-Domains (selective clean; a fresh run "
                        "wipes only their data/clean/<domain>/ folders)")
    c.add_argument("--sources-only", nargs="*", default=None,
                   help="clean only these specific raw source folders, each given "
                        "as 'sub-domain/source' (row-level clean; takes precedence "
                        "over --domains). A fresh run wipes only their "
                        "data/clean/<sub-domain>/<source>/ folders.")
    c.add_argument("--cap", type=int, default=None,
                   help="max records per domain (balance action)")
    c.add_argument("--source-share", type=float, default=None, metavar="SHARE",
                   help="balance action: downsample any single source above SHARE "
                        "(e.g. 0.6) of its subdomain. Opt-in - destroys data when "
                        "secondary sources are small; prefer adding sources.")
    c.add_argument("--min-text-chars", type=int, default=None,
                   help="below this many chars after sanitize -> structural drop "
                        "(default 50)")
    c.add_argument("--max-text-chars", type=int, default=None,
                   help="above this many chars -> behavioral flag, extreme length "
                        "(default 100000)")
    c.add_argument("--garbage-max", type=float, default=None,
                   help="max fraction of non-text chars before a behavioral flag "
                        "(default 0.30)")
    c.add_argument("--repeat-max", type=float, default=None,
                   help="max fraction of repeated lines/tokens before a behavioral "
                        "flag (default 0.50)")
    c.add_argument("--near-dup-threshold", type=float, default=None,
                   help="Jaccard similarity threshold for near-duplicates "
                        "(default 0.85)")
    c.add_argument("--shingle-size", type=int, default=None,
                   help="word-shingle length for MinHash near-dup (default 5)")
    c.add_argument("--minhash-perm", type=int, default=None,
                   help="MinHash permutation count (default 128)")
    c.add_argument("--allowed-langs", nargs="*", default=None,
                   help="language codes to keep (default: en)")
    c.add_argument("--pii-engine", choices=("regex", "presidio"), default=None,
                   help="PII redaction engine (default: regex). 'presidio' adds a "
                        "scoped spaCy NER pass for person names on top of the regex "
                        "pass, at roughly 300x the cost per record; needs "
                        "`uv sync --extra pii-ner`")

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
    ed.add_argument("--min-total-records", type=int, default=None,
                    help="sufficiency gate: minimum total records (default 50)")
    ed.add_argument("--min-records-per-subdomain", type=int, default=None,
                    help="sufficiency gate: minimum records per sub-domain (default 5)")
    ed.add_argument("--max-source-share", type=float, default=None,
                    help="max share of a sub-domain one source may hold (default 0.60)")
    ed.add_argument("--max-drift", type=float, default=None,
                    help="max topic-mix drift vs the previous run (default 0.25)")
    ed.add_argument("--max-dup-rate", type=float, default=None,
                    help="max exact-duplicate rate before a violation (default 0.40)")
    ed.add_argument("--min-avg-tokens", type=float, default=None,
                    help="minimum average tokens per record (default 5.0)")
    ed.add_argument("--max-topic-cv", type=float, default=None,
                    help="max coefficient of variation across topic sizes (default 1.5)")
    ed.add_argument("--min-subdomain-share", type=float, default=None,
                    help="minimum share of the corpus a sub-domain must hold (default 0.01)")
    ed.add_argument("--owner", default=None,
                    help="team name recorded on the EDA report (default: "
                         "data-collection-team)")

    # ── validate ──────────────────────────────────────────────────────────────
    sub.add_parser("validate",
                   help="validate data/clean/ records against Pydantic schema")

    # ── ingest (stage 2: fetch-only) ──────────────────────────────────────────
    ig = sub.add_parser("ingest",
                        help="fetch all sources -> data/raw/ (stage 2; no cleaning)")
    ig.add_argument("--sources", default=None,
                    help="path to a sources .csv (default: the active profile's Sources.csv)")
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
    ig.add_argument("--no-crawler", action="store_true",
                    help="skip website (crawl) sources for this run")
    ig.add_argument("--no-hazard-scan", action="store_true",
                    help="skip the security-hazard scan (script/iframe injection, "
                         "base64 blobs, malware TLDs) during the light-EDA gate; "
                         "default: scan")
    ig.add_argument("--extractor", choices=("default", "trafilatura"),
                    default=None,
                    help="how a crawled page becomes text. 'default' strips known "
                         "boilerplate tags and keeps the rest; 'trafilatura' "
                         "detects the main content, dropping menus/sidebars/cookie "
                         "banners the tag list cannot see (needs the 'crawl' extra; "
                         "falls back to default if absent). Affects website sources "
                         "only, on re-crawl.")
    ig.add_argument("--domains", nargs="*", default=None,
                    help="fetch only these Sub-Domains (selective ingest; a fresh "
                         "run wipes only their data/raw/<domain>/ folders)")
    ig.add_argument("--sources-only", nargs="*", default=None,
                    help="fetch only these specific sources, by catalog Dataset "
                         "Link/URL (row-level ingest; combine with --domains to "
                         "scope within Sub-Domains). A fresh row-level run wipes "
                         "nothing and re-fetches just the chosen sources.")

    # ── source (SearXNG source discovery) ────────────────────────────────────
    d = sub.add_parser("source",
                       help="search SearXNG by keyword -> append new rows to Sources.csv")
    d.add_argument("--sources", default=None,
                   help="catalog CSV to append to (default: the active profile's Sources.csv)")
    d.add_argument("--domains", nargs="*", default=None,
                   help="limit to these Sub-Domains (default: all)")
    d.add_argument("--mode", choices=["datasets", "text", "both"], default="datasets",
                   help="keyword catalog: datasets (corpora/repos), text "
                        "(articles/docs), or both (default: datasets)")
    d.add_argument("--per-keyword", type=int, default=5,
                   help="results to request per keyword (default 5)")
    d.add_argument("--max-per-domain", type=int, default=None,
                   help="cap new rows kept per Sub-Domain")
    d.add_argument("--max-total", type=int, default=None,
                   help="stop the whole run after this many new rows (all domains). "
                        "In fill mode this caps the total commercial-valid rows")
    d.add_argument("--target-per-domain", type=int, default=None,
                   help="fill mode: top each Sub-Domain up to this many "
                        "commercial-valid rows total (reads existing counts and "
                        "fills only the deficit); stops a domain at the target or "
                        "when its search is exhausted")
    d.add_argument("--engines", default=None,
                   help="comma-separated SearXNG engines to query (env: "
                        "SEARXNG_ENGINES; default a GitHub-first reliable set). "
                        "Routes around the rate-limited general web engines")
    d.add_argument("--max-minutes", type=float, default=None,
                   help="time budget: stop the run after this many minutes "
                        "(combine with --max-total; whichever is hit first wins)")
    d.add_argument("--workers", type=int, default=None,
                   help="enrichment thread-pool size (default 12); higher = faster "
                        "license/metadata fetch")
    d.add_argument("--time-range", choices=["any", "day", "week", "month", "year"],
                   default="year",
                   help="freshness bias: prefer results within this window "
                        "(any = no filter; default year). Falls back to unfiltered "
                        "when a query would return nothing")
    d.add_argument("--no-site-scope", action="store_true",
                   help="do not scope datasets-mode queries to licensable hosts "
                        "(HuggingFace, GitHub, Kaggle, Zenodo, arXiv, data.gov, UCI)")
    d.add_argument("--no-quality-filter", action="store_true",
                   help="keep low-quality results (social/listing/search pages) "
                        "instead of dropping them before enrichment")
    d.add_argument("--dry-run", action="store_true",
                   help="discover + write CSV but do not append to Sources.csv")
    d.add_argument("--out", default=None,
                   help="path for the candidate CSV (default: logs/discovered/)")
    d.add_argument("--searxng-url", default=None,
                   help="SearXNG base URL (env: SEARXNG_URL; default http://localhost:8080)")
    d.add_argument("--language", default="en",
                   help="SearXNG search language (default: en)")
    d.add_argument("--no-enrich", action="store_true",
                   help="skip fetching per-source metadata (size, license, last "
                        "updated, author, popularity, tags) from the source host; "
                        "faster, but leaves those columns blank")
    d.add_argument("--backfill", action="store_true",
                   help="instead of discovery, deep-detect licenses for existing "
                        "catalog rows (blank/Unknown by default) and move any "
                        "confirmed-red source to the profile's Blacklist.csv")
    d.add_argument("--backfill-all", action="store_true",
                   help="with --backfill, re-detect every row's license, not just "
                        "the blank/Unknown ones")
    d.add_argument("--no-blacklist", action="store_true",
                   help="with --backfill, detect licenses only; do not move "
                        "confirmed-red sources to the blacklist")
    d.add_argument("--limit", type=int, default=None,
                   help="with --backfill, detect at most this many rows (a sample)")

    # ── synthetic-scan (curation aid) ─────────────────────────────────────────
    ss = sub.add_parser("synthetic-scan",
                        help="suggest which sources look synthetic (keyword scan "
                             "of Sources.csv); propose-only unless --apply")
    ss.add_argument("--sources", default=None,
                    help="catalog CSV to scan (default: the active profile's Sources.csv)")
    ss.add_argument("--apply", action="store_true",
                    help="write Is Synthetic?=Yes for high-confidence gaps "
                         "(review-level matches are never auto-applied)")

    # ── review (model-judged curation aid) ────────────────────────────────────
    rv = sub.add_parser("review",
                        help="judge each catalogued source against a plain-English "
                             "condition with a model; propose-only unless --apply")
    rv.add_argument("--condition", default=None,
                    help='what a source must satisfy to stay, in plain English '
                         '(e.g. "the data must concern India"). Required unless '
                         "--apply replays an existing report.")
    rv.add_argument("--sources", default=None,
                    help="catalog CSV to review (default: the active profile's "
                         "Sources.csv)")
    rv.add_argument("--apply", action="store_true",
                    help="move declined sources to the profile's Excluded.csv. "
                         "With --condition it re-reviews then applies; alone it "
                         "replays the newest report, so what you read is what is "
                         "applied. Low-confidence and 'review' verdicts never move.")
    rv.add_argument("--report", default=None,
                    help="with --apply alone, the report to replay "
                         "(default: the newest under logs/reviews/)")

    # ── profile (switch which corpus the pipeline builds) ─────────────────────
    pr = sub.add_parser("profile",
                        help="list / show / switch the pipeline profile "
                             "(which corpus every stage works on)")
    pr_sub = pr.add_subparsers(dest="action", required=False)
    pr_sub.add_parser("list", help="list every known profile (default action)")
    pr_show = pr_sub.add_parser("show", help="show one profile's taxonomy and catalog")
    pr_show.add_argument("name", nargs="?", default=None,
                         help="profile to show (default: the active one)")
    pr_use = pr_sub.add_parser("use", help="switch the active profile")
    pr_use.add_argument("name", help="profile to activate")
    pr_new = pr_sub.add_parser("create", help="start a new, empty profile")
    pr_new.add_argument("name", help="name for the new profile")
    pr_new.add_argument("--domain-name", default="",
                        help="schema domain_name label (default: NAME upper-cased)")
    pr_new.add_argument("--use", action="store_true",
                        help="activate the new profile straight away")

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
                       help="full corpus build: ingest -> clean -> EDA -> schema "
                            "(4 stages; run `source` separately to curate first)")
    a.add_argument("--sources", default=None,
                   help="path to a sources .csv (default: the active profile's Sources.csv)")
    a.add_argument("--workers", type=int, default=None,
                   help="ingest process pool size (default: min(cpu, 8))")
    a.add_argument("--clean-workers", type=int, default=_DEFAULT_CLEAN_WORKERS,
                   help="clean-stage process pool size (default: physical cores, "
                        "max 8; pass 1 to force sequential). Cleaning is per-source and "
                        "the cross-source dedup pass runs once afterward, so more "
                        "workers speed cleaning up without changing the output")
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
    a.add_argument("--no-crawler", action="store_true",
                   help="skip website (crawl) sources during ingest for this run")
    a.add_argument("--pii-engine", choices=("regex", "presidio"), default=None,
                   help="PII redaction engine for the clean stage (default: regex). "
                        "'presidio' adds a scoped spaCy NER pass for person names at "
                        "roughly 300x the cost per record; needs "
                        "`uv sync --extra pii-ner`")
    a.add_argument("--no-hazard-scan", action="store_true",
                   help="skip the security-hazard scan (script/iframe injection, "
                        "base64 blobs, malware TLDs) during the light-EDA gate; "
                        "default: scan")
    return p


def _run_profile(args) -> None:
    """``profile list|show|use|create`` — inspect or switch the active corpus."""
    from .sourcing import profiles

    action = getattr(args, "action", None) or "list"

    if action == "list":
        active = profiles.active()
        for name in profiles.names():
            info = profiles.info(name)
            mark = "*" if name == active else " "
            kind = "built-in" if info["builtin"] else "custom"
            print(f"{mark} {name:<12} {info['domain_name']:<20} "
                  f"{len(info['subdomains'])} sub-domains, "
                  f"{info['catalog_rows']} sources ({kind})")
        print("\n* = active. Switch with: cybersec-slm profile use <name>")
        return

    if action == "show":
        info = profiles.info(args.name or profiles.active())
        print(f"profile     : {info['name']}{' (active)' if info['active'] else ''}")
        print(f"domain_name : {info['domain_name']}")
        print(f"directory   : {info['dir']}")
        print(f"catalog rows: {info['catalog_rows']}")
        print("sub-domains :")
        for sub in info["subdomains"]:
            print(f"  - {sub}")
        return

    if action == "use":
        try:
            name = profiles.use(args.name)
        except (profiles.UnknownProfile, ValueError) as e:
            raise SystemExit(str(e)) from None
        info = profiles.info(name)
        print(f"active profile -> {name} ({info['domain_name']}, "
              f"{len(info['subdomains'])} sub-domains, {info['catalog_rows']} sources)")
        return

    if action == "create":
        try:
            d = profiles.create(args.name, domain_name=args.domain_name,
                                use_it=args.use)
        except (FileExistsError, ValueError) as e:
            raise SystemExit(str(e)) from None
        print(f"created profile {args.name!r} at {d}")
        print("It has no sub-domains yet — add them on the dashboard's Sourcing "
              "page, or edit keywords.yaml in that directory.")


def _migrate_layout() -> None:
    """Move a pre-profile ``data/``/``logs/`` under the active profile, if needed.

    Best-effort and loud: if the rename fails (on Windows, a process still holding
    a log file open), say so and carry on with whatever layout is there rather than
    refusing to run. Nothing is copied or deleted, so a failed attempt leaves the
    corpus exactly as it was.
    """
    from . import core
    try:
        moved = core.migrate_layout()
    except OSError as e:
        core.logger.warning(
            f"could not move the corpus under its profile ({e}); it is untouched. "
            f"Close any running pipeline and retry.")
        return
    if moved:
        core.logger.info(
            f"moved {', '.join(moved)}/ under profile {core.active_profile()!r}: "
            f"each profile now keeps its own corpus and logs")


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)

    # Move a pre-profile corpus under its profile, once, before any stage reads a
    # path. Here rather than at core's import because a ProcessPoolExecutor worker
    # re-imports core, and several processes racing to rename the same tree is how
    # you lose it. This is the single-process entry point every stage comes
    # through, and it is a no-op once the move has happened.
    _migrate_layout()

    # The crawl extractor travels by environment, not by argument: the chain from
    # here to the choice is run_ingest -> pool worker -> crawl subprocess, and the
    # environment already crosses both boundaries. Same idiom as
    # $CYBERSEC_SLM_TRANSLATE / $CYBERSEC_SLM_PII_MAX_CHARS.
    if getattr(args, "extractor", None):
        os.environ["CYBERSEC_SLM_EXTRACTOR"] = args.extractor

    if args.stage == "profile":
        _run_profile(args)

    elif args.stage == "clean":
        if args.action is None:
            # Stage 3: clean the whole raw tree + cross-source dedup.
            from .cleaning import common as clean_common
            _apply_pii_engine(args)
            if args.min_text_chars is not None:
                clean_common.MIN_TEXT_CHARS = args.min_text_chars
            if args.max_text_chars is not None:
                clean_common.MAX_TEXT_CHARS = args.max_text_chars
            if args.garbage_max is not None:
                clean_common.GARBAGE_MAX = args.garbage_max
            if args.repeat_max is not None:
                clean_common.REPEAT_MAX = args.repeat_max
            if args.near_dup_threshold is not None:
                clean_common.NEAR_DUP_THRESHOLD = args.near_dup_threshold
            if args.shingle_size is not None:
                clean_common.SHINGLE_SIZE = args.shingle_size
            if args.minhash_perm is not None:
                clean_common.MINHASH_PERM = args.minhash_perm
            if args.allowed_langs:
                clean_common.LANGS = set(args.allowed_langs)

            from .ingestion import parallel
            parallel.run_clean(keep_raw=not args.purge_raw, limit=args.limit,
                               resume=args.resume,
                               drop_non_english=args.drop_non_english,
                               domains=args.domains,
                               sources_only=args.sources_only,
                               workers=args.workers)
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
                            max_source_gb=args.max_source_gb,
                            crawl=not args.no_crawler,
                            domains=args.domains,
                            sources_only=args.sources_only,
                            scan_hazards=not args.no_hazard_scan)

    elif args.stage in ("normalize", "schema"):
        from .normalize import run_normalization
        run_normalization(args.input, resume=not args.fresh, limit=args.limit)

    elif args.stage == "eda":
        from .eda import config as eda_config
        if getattr(args, "no_auto_rebalance", False):
            eda_config.AUTO_REBALANCE = False
        if args.min_total_records is not None:
            eda_config.MIN_TOTAL_RECORDS = args.min_total_records
        if args.min_records_per_subdomain is not None:
            eda_config.MIN_RECORDS_PER_SUBDOMAIN = args.min_records_per_subdomain
        if args.max_source_share is not None:
            eda_config.MAX_SOURCE_SHARE = args.max_source_share
        if args.max_drift is not None:
            eda_config.MAX_DRIFT = args.max_drift
        if args.max_dup_rate is not None:
            eda_config.MAX_DUP_RATE = args.max_dup_rate
        if args.min_avg_tokens is not None:
            eda_config.MIN_AVG_TOKENS = args.min_avg_tokens
        if args.max_topic_cv is not None:
            eda_config.MAX_TOPIC_CV = args.max_topic_cv
        if args.min_subdomain_share is not None:
            eda_config.MIN_SUBDOMAIN_SHARE = args.min_subdomain_share
        if args.owner is not None:
            eda_config.OWNER = args.owner
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

    elif args.stage == "review":
        from .sourcing import review as _review
        if args.condition:
            out = _review.run_scan(args.condition, args.sources, apply=args.apply)
            c = out["counts"]
            print(f"review: approve={c['approve']} decline={c['decline']} "
                  f"review={c['review']}  ->  {out['report']}")
            if not args.apply:
                print(f"review: propose-only; re-run with --apply to move the "
                      f"{c['decline']} declined source(s)")
        elif args.apply:
            # Replay a recorded report: no second, different set of model calls,
            # so what was read is exactly what is applied.
            res = _review.apply_report(args.report, spec=args.sources)
            if not res["report"]:
                raise SystemExit("review: no report to apply — run "
                                 '`review --condition "..."` first')
            print(f"review: moved {res['moved']} source(s) from "
                  f"{os.path.basename(res['report'])}")
        else:
            raise SystemExit('review: pass --condition "..." to review the '
                             "catalog, or --apply to replay the newest report")

    elif args.stage == "dashboard":
        from .dashboard.launch import launch
        launch(port=args.port, headless=args.headless)

    elif args.stage == "source" and getattr(args, "backfill", False):
        from .sourcing import backfill_licenses
        summary = backfill_licenses(
            args.sources, only_blank=not args.backfill_all, limit=args.limit,
            dry_run=args.dry_run, then_blacklist=not args.no_blacklist)
        print(f"source: backfill scanned {summary['scanned']}, "
              f"detected {summary['detected']}, "
              f"still unknown {summary['still_unknown']}, "
              f"blacklisted {summary['blacklisted']}"
              f"{' (dry-run)' if summary['dry_run'] else ''} -> {summary['summary']}")

    elif args.stage == "source":
        from .sourcing import run as sourcing
        from .sourcing.search import SearchError
        try:
            summary = sourcing.discover(
                args.sources, domains=args.domains,
                per_keyword=args.per_keyword, max_per_domain=args.max_per_domain,
                max_total=args.max_total, max_minutes=args.max_minutes,
                mode=args.mode, dry_run=args.dry_run,
                out_csv=args.out, base_url=args.searxng_url, language=args.language,
                time_range=(None if args.time_range == "any" else args.time_range),
                site_scope=not args.no_site_scope,
                quality_filter=not args.no_quality_filter,
                workers=args.workers or 12, enrich=not args.no_enrich,
                engines=args.engines, target_per_domain=args.target_per_domain)
        except SearchError as e:
            raise SystemExit(f"source: discovery could not run: {e}") from None
        print(f"source: {summary['found']} hits, {summary['new']} new, "
              f"{summary['appended']} appended, {summary['license_filled']} licensed "
              f"({summary['license_rate']:.0%}) in {summary['elapsed_s']}s "
              f"-> {summary['csv']}")

    elif args.stage == "all":
        # Full corpus build: ingest -> clean -> EDA -> schema (four stages, no
        # overlap). Sourcing is a separate curation step (`cybersec-slm source`).
        if getattr(args, "no_auto_rebalance", False):
            from .eda import config as eda_config
            eda_config.AUTO_REBALANCE = False
        _apply_pii_engine(args)
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
            crawl=not args.no_crawler,
            scan_hazards=not args.no_hazard_scan,
            clean_workers=args.clean_workers,
        )


if __name__ == "__main__":
    main()
