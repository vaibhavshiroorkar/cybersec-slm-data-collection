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


PERMITTED_ROTATORS = {
    # Add mapped scripts here. They must be absolute paths to trusted local scripts.
    # e.g., "github_app": [sys.executable, os.path.join(REPO_ROOT, "tools", "rotate_github_app.py")]
}

def rotate_credential(source: str, fields: dict) -> bool:
    """Attempt to programmatically rotate a credential.
    Executes a pre-approved script if provided in 'rotation_handler'.
    Returns True if successfully rotated and fields were updated in-place.
    """
    handler = fields.get("rotation_handler")
    if not handler:
        print(f"[{source}] No rotation_handler configured, skipping auto-rotation.", file=sys.stderr)
        return False
        
    cmd = PERMITTED_ROTATORS.get(handler)
    if not cmd:
        print(f"[{source}] Unknown or forbidden rotation_handler '{handler}'.", file=sys.stderr)
        return False
        
    print(f"[{source}] Initiating credential rotation via handler '{handler}'...", file=sys.stderr)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if proc.returncode == 0:
            new_val = proc.stdout.strip()
            if new_val:
                fields["value"] = new_val
                fields["rotated_at"] = dt.date.today().isoformat()
                if fields.get("expires_at"):
                    fields["expires_at"] = (dt.date.today() + dt.timedelta(days=90)).isoformat()
                return True
        else:
            print(f"[{source}] Rotation failed: {proc.stderr}", file=sys.stderr)
    except Exception as e:
        print(f"[{source}] Error executing rotation: {e}", file=sys.stderr)
    return False

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
    needs_save = False

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
            if rotate_credential(source, fields):
                needs_save = True
                ok.append(f"{source}: Auto-rotated successfully today (new expiry {fields.get('expires_at')})")
                continue

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

    if needs_save:
        plain_path = os.path.join(REPO_ROOT, "secrets", "credentials.yaml")
        with open(plain_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(creds, f, sort_keys=False)
        enc_proc = subprocess.run(["sops", "-e", "-i", plain_path], capture_output=True, text=True)
        if enc_proc.returncode == 0:
            os.replace(plain_path, ENC_PATH)
            print("\nSuccessfully rotated and saved new credentials to SOPS.", file=sys.stderr)
        else:
            print(f"\nFailed to encrypt new credentials: {enc_proc.stderr}", file=sys.stderr)
            return 1

    if problems:
        print(f"\n{len(problems)} credential(s) need rotation.")
        return 1
    print("\nAll credentials are fine.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
