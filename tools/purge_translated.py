#!/usr/bin/env python3
"""Remove machine-translated records from data/clean/ (propose-only by default).

Why this exists
---------------
The cleaning pass has two language policies. By default a confidently non-English
record is *translated* into English and kept, stamped with ``_orig_lang``; with
``--drop-non-english`` it is dropped instead and the translator is never called.

Switching policy mid-corpus leaves a mixed corpus: the sources cleaned before the
switch keep their translated records, the ones after drop them. Re-cleaning
everything would fix it, but throws away every already-cleaned source. Every
translated record is identifiable by ``_orig_lang``, so this rewrites just the
affected files instead -- minutes rather than days.

Purged records are appended to ``data/dropped/<rel>`` with a ``_stage`` /
``_reason``, exactly as the cleaning pass annotates its own drops, so they stay
inspectable rather than vanishing.

Run from the repo root::

    python tools/purge_translated.py            # report what WOULD go
    python tools/purge_translated.py --apply    # rewrite the files

Safe to run while a clean pass is in flight: ``_orig_lang`` can only exist in
sources cleaned under the old policy, which are already finished (a resumed pass
skips them via the ledger and never reopens their output).
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if os.path.join(_ROOT, "src") not in sys.path:
    sys.path.insert(0, os.path.join(_ROOT, "src"))

MARKER = "_orig_lang"
REASON = "machine-translated record purged (drop-non-english policy)"


def _has_marker(path: str) -> bool:
    """Cheap pre-filter: does the file mention the marker at all?

    Avoids JSON-parsing every record of every file just to discover that almost
    none of them were translated.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return any(f'"{MARKER}"' in line for line in f)
    except OSError:
        return False


def find_files(clean_root: str) -> list[str]:
    """Every .jsonl under `clean_root` holding at least one translated record."""
    from cybersec_slm.cleaning.common import SCRATCH_DIRS

    out: list[str] = []
    for root, dirs, files in os.walk(clean_root):
        dirs[:] = [d for d in dirs if d not in SCRATCH_DIRS]
        for name in files:
            if name.endswith(".jsonl"):
                path = os.path.join(root, name)
                if _has_marker(path):
                    out.append(path)
    return sorted(out)


def purge_file(path: str, *, clean_root: str, dropped_root: str,
               apply: bool = False) -> tuple[int, int]:
    """``(kept, purged)`` for one file; rewrites it only when ``apply``.

    The rewrite is atomic (temp file + replace) so an interrupted run can never
    leave a half-written corpus file behind.
    """
    from cybersec_slm.core import PARSE_ERROR, iter_jsonl, json_dumps

    rel = os.path.relpath(path, clean_root).replace("\\", "/")
    kept_recs: list[dict] = []
    purged_recs: list[dict] = []
    for rec in iter_jsonl(path):
        if rec.get(PARSE_ERROR):
            kept_recs.append(rec)               # not ours to judge; leave as-is
            continue
        if rec.get(MARKER):
            purged_recs.append(rec)
        else:
            kept_recs.append(rec)

    if not purged_recs or not apply:
        return len(kept_recs), len(purged_recs)

    dropped_path = os.path.join(dropped_root, rel)
    os.makedirs(os.path.dirname(dropped_path) or ".", exist_ok=True)
    with open(dropped_path, "a", encoding="utf-8") as f:
        for rec in purged_recs:
            f.write(json_dumps({**rec, "_stage": "langfilter",
                                "_reason": REASON}) + "\n")

    fd, tmp = tempfile.mkstemp(suffix=".jsonl.tmp", dir=os.path.dirname(path))
    os.close(fd)
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            for rec in kept_recs:
                f.write(json_dumps(rec) + "\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    return len(kept_recs), len(purged_recs)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--apply", action="store_true",
                    help="rewrite the files (default: report only)")
    args = ap.parse_args(argv)

    from cybersec_slm import core

    clean_root, dropped_root = core.CLEAN_DATA, core.DROPPED
    files = find_files(clean_root)
    if not files:
        print("no translated records under data/clean -- nothing to purge")
        return

    total_purged = total_kept = 0
    for path in files:
        kept, purged = purge_file(path, clean_root=clean_root,
                                  dropped_root=dropped_root, apply=args.apply)
        total_kept += kept
        total_purged += purged
        rel = os.path.relpath(path, clean_root)
        print(f"  {'purged' if args.apply else 'would purge'} {purged:>6} "
              f"(keeping {kept:>7})  {rel}")

    verb = "purged" if args.apply else "would purge"
    print(f"\n{verb} {total_purged:,} translated record(s) across {len(files)} "
          f"file(s); {total_kept:,} kept")
    if not args.apply:
        print("re-run with --apply to rewrite the files")
    else:
        print(f"purged records appended under {os.path.relpath(dropped_root)}/")


if __name__ == "__main__":
    main()
