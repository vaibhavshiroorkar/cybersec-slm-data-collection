#!/usr/bin/env python3
"""Warn when a credential in secrets/credentials.enc.yaml is near or past expiry."""
from __future__ import annotations

import datetime as dt
import os
import subprocess
import sys

import yaml

WARN_DAYS_BEFORE = 14
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENC_PATH = os.path.join(REPO_ROOT, "secrets", "credentials.enc.yaml")


def main() -> int:
    if not os.path.exists(ENC_PATH):
        print(f"no {ENC_PATH} found -- nothing to check")
        return 0

    proc = subprocess.run(
        ["sops", "-d", ENC_PATH], capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        print(f"could not decrypt {ENC_PATH}: {proc.stderr.strip()}", file=sys.stderr)
        return 1

    creds = yaml.safe_load(proc.stdout) or {}
    today = dt.date.today()
    problems: list[str] = []
    ok: list[str] = []

    for source, fields in creds.items():
        if not isinstance(fields, dict):
            continue
        expires_at = fields.get("expires_at")
        if not expires_at:
            ok.append(f"{source}: no provider-enforced expiry (rotated_at={fields.get('rotated_at')})")
            continue
        expiry = dt.date.fromisoformat(str(expires_at))
        days_left = (expiry - today).days
        
        if days_left <= WARN_DAYS_BEFORE:
            if days_left < 0:
                problems.append(f"{source}: EXPIRED {abs(days_left)} day(s) ago ({expiry})")
            else:
                problems.append(f"{source}: expires in {days_left} day(s) ({expiry}) -- rotate now")
        else:
            ok.append(f"{source}: expires {expiry} ({days_left} days out)")

    for line in ok:
        print(f"  ok    - {line}")
    for line in problems:
        print(f"  ACTION - {line}")

    if problems:
        print(f"\n{len(problems)} credential(s) need rotation.")
        return 1
    print("\nAll credentials are fine.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
