#!/usr/bin/env python3
"""Regenerate sources/allowlist.yaml from the catalog (sources/Sources.csv).

Every catalog source is seeded with ``--status`` (default ``approved``). Review the
diff before committing — adding an approved source is a security decision, so prefer
``--status pending`` for a freshly-discovered catalog and approve rows deliberately.

    python tools/build_allowlist.py            # write sources/allowlist.yaml
    python tools/build_allowlist.py --stdout   # print, don't write
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cybersec_slm.extraction.allowlist import DEFAULT_ALLOWLIST, dump_allowlist_yaml  # noqa: E402
from cybersec_slm.extraction.sources import DEFAULT_CATALOG, load_descriptors  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--status", default="approved",
                    choices=["approved", "pending", "rejected"])
    ap.add_argument("--stdout", action="store_true", help="print instead of writing")
    args = ap.parse_args()

    text = dump_allowlist_yaml(load_descriptors(DEFAULT_CATALOG), status=args.status)
    if args.stdout:
        print(text)
        return
    with open(DEFAULT_ALLOWLIST, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {DEFAULT_ALLOWLIST}")


if __name__ == "__main__":
    main()
