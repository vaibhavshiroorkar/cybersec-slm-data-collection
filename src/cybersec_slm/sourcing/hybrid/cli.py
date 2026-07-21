"""
cli.py – CLI entry point for `cybersec-slm hybrid-source`.

Usage:
    uv run cybersec-slm hybrid-source --config path/to/hybrid_config.yaml
    uv run cybersec-slm hybrid-source --config ... --dry-run
    uv run cybersec-slm hybrid-source --config ... --limit 100
    uv run cybersec-slm hybrid-source --config ... --out custom.csv
"""

from __future__ import annotations

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cybersec-slm hybrid-source",
        description=(
            "Generalized hybrid sourcer: fills a Sources.csv catalog "
            "using URL patterns, HuggingFace/GitHub/arXiv APIs, CKAN, "
            "and SearXNG — driven entirely by a YAML config file."
        ),
    )
    p.add_argument(
        "--config", "-c",
        required=True,
        metavar="YAML",
        help="Path to the hybrid_config.yaml file describing the domain.",
    )
    p.add_argument(
        "--out", "-o",
        metavar="CSV",
        default=None,
        help="Override the output CSV path from the config.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Print the backend plan and keyword summary without writing anything.",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Stop after adding this many NEW rows (useful for testing).",
    )
    p.add_argument(
        "--quiet", "-q",
        action="store_true",
        default=False,
        help="Suppress progress output.",
    )
    p.add_argument(
        "--parallel",
        action="store_true",
        default=False,
        help=(
            "Fetch from all planned backends concurrently instead of one at "
            "a time. Each backend hits an independent API/rate-limit, so "
            "wall-clock time drops from sum(latency) to roughly max(latency). "
            "Recommended once GITHUB_TOKEN is set, since the slowest backend "
            "(unauthenticated GitHub) is the usual bottleneck in sequential mode."
        ),
    )
    return p


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

    parser = build_parser()
    args = parser.parse_args(argv)

    # Load config
    from .config import load_config
    try:
        cfg = load_config(args.config)
    except FileNotFoundError:
        print(f"ERROR: Config file not found: {args.config}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"ERROR loading config: {exc}", file=sys.stderr)
        return 1

    # Override output path
    if args.out:
        cfg.output_csv = args.out

    # Run
    from .coordinator import HybridSourcer
    sourcer = HybridSourcer(cfg, verbose=not args.quiet)

    try:
        total = sourcer.run(dry_run=args.dry_run, limit=args.limit,
                           parallel=args.parallel)
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Partial results written.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"\nERROR during sourcing: {exc}", file=sys.stderr)
        raise

    return 0


if __name__ == "__main__":
    raise SystemExit(main())