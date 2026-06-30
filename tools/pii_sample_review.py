#!/usr/bin/env python3
"""Sample random cleaned records for manual PII false-negative review.

Presidio's blind spots for security data (hostnames, private IPs, service
usernames) are false negatives, so periodic human review of a random slice is the
backstop (see docs/pii_limitations.md). This pulls a uniform reservoir sample and
flags any lines that match the known blind-spot patterns to focus the review.

    python tools/pii_sample_review.py --n 200
    python tools/pii_sample_review.py --input cleaned --n 100
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cybersec_slm.cleaning.common import find_input_files, text_of  # noqa: E402
from cybersec_slm.core import CLEAN_DATA, CLEANED, LOGS, iter_jsonl  # noqa: E402

# Heuristic blind-spot patterns (recall-oriented; review confirms true positives).
_PATTERNS = {
    "private_ip": re.compile(r"\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"),
    "internal_host": re.compile(r"\b[a-z0-9-]+\.(?:corp|internal|local|lan)\b", re.I),
    "mac_addr": re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"),
    "win_userpath": re.compile(r"[A-Za-z]:\\Users\\[^\\\s]+", re.I),
    "nix_userpath": re.compile(r"/home/[^/\s]+"),
    "service_user": re.compile(r"\b(?:svc|service|admin|root|test)[_-][a-z0-9]+\b", re.I),
}


def _resolve_input(name: str | None) -> str:
    if name:
        return name
    if os.path.isdir(CLEAN_DATA) and any(os.scandir(CLEAN_DATA)):
        return CLEAN_DATA
    return CLEANED


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", default=None,
                    help="cleaned root (default data/clean/ then cleaned/)")
    ap.add_argument("--n", type=int, default=200, help="sample size")
    ap.add_argument("--seed", type=int, default=None, help="RNG seed for a reproducible sample")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    root = _resolve_input(args.input)
    reservoir: list[dict] = []
    seen = 0
    for ap_, sub, source, _rel in find_input_files(root):
        for rec in iter_jsonl(ap_):
            if rec.get("_parse_error"):
                continue
            t = text_of(rec)
            if not t:
                continue
            seen += 1
            item = {"subdomain": sub, "source": source, "text": t}
            if len(reservoir) < args.n:
                reservoir.append(item)
            else:                                    # reservoir sampling
                j = rng.randint(0, seen - 1)
                if j < args.n:
                    reservoir[j] = item

    flagged = 0
    for item in reservoir:
        hits = sorted(name for name, rx in _PATTERNS.items() if rx.search(item["text"]))
        item["blind_spot_hits"] = hits
        flagged += bool(hits)

    out_dir = os.path.join(LOGS, "pii_review")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, f"sample-{time.strftime('%Y%m%dT%H%M%S')}.jsonl")
    with open(out, "w", encoding="utf-8") as f:
        for item in reservoir:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    print(f"scanned {seen} records from {root}")
    print(f"sample of {len(reservoir)} written -> {out}")
    print(f"{flagged} sampled records matched a known blind-spot pattern — review these first")


if __name__ == "__main__":
    main()
