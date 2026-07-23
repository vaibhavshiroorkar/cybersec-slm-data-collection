#!/usr/bin/env python3
"""Security (page 7): every control, proved by exercising it.

Each row runs a real probe against the thing the control is supposed to refuse,
so a control that breaks turns its row red. A checklist would keep saying
"present" over a deleted function, which is not a theoretical worry here: the
hazard scanner's own docstring described a quarantine that nothing ever wrote.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import security, ui
from cybersec_slm.ingestion import binscan

ui.inject_css()
# app_header, not page_header: Security is not one of the five pipeline stages, so
# it has no stage key, no sequence number and no run state to show a pill for.
ui.app_header("Security",
              "Every control below is exercised, not merely listed: each probe "
              "makes the control refuse something and reports what happened.")

# ------------------------------------------------------------- the probes -----
with ui.section("Controls",
                "Run on every page load. Offline, and they never touch the "
                "corpus: each builds its own input in a temp directory."):
    probes = security.run_probes()
    failed = [p for p in probes if not p.passed]

    if failed:
        st.error(f"{len(failed)} of {len(probes)} controls are not working: "
                 + ", ".join(p.name for p in failed))
    else:
        st.success(f"All {len(probes)} controls verified.")

    ui.table([{"control": p.name,
               "state": "PASS" if p.passed else "FAIL",
               "finding": p.finding or "",
               "what was proved": p.detail} for p in probes], height=340)

# ------------------------------------------------------- binaries reported ----
with ui.section("Binaries in fetched archives",
                "Sources that shipped an executable. They are reported, never "
                "ingested, and never executed. `logs/binary_scan.jsonl`."):
    found = binscan.findings()
    if not found:
        st.caption("No source has shipped a binary yet, or ingestion has not run "
                   "since the scanner was added.")
    else:
        st.warning(f"{len(found)} source(s) shipped binaries.")
        ui.table([{"source": e.get("source", ""),
                   "sub-domain": e.get("domain", ""),
                   "binaries": e.get("total", 0),
                   "kinds": ", ".join(f"{k}x{n}" for k, n
                                      in sorted((e.get("by_kind") or {}).items())),
                   "when": e.get("ts", "")} for e in reversed(found)], height=240)
        with st.expander("Every reported file"):
            ui.table([{"source": e.get("source", ""), "kind": f.get("kind", ""),
                       "bytes": f.get("size", 0), "path": f.get("path", "")}
                      for e in reversed(found) for f in (e.get("findings") or [])],
                     height=300)

# --------------------------------------------------------- the threat model ---
with ui.section("Threat model checklist",
                "Read from `docs/security-requirements.md`, so this page cannot "
                "claim a box the document does not."):
    rows = security.checklist()
    if not rows:
        st.caption("No checklist found in `docs/security-requirements.md`.")
    else:
        done = sum(1 for r in rows if r["done"])
        st.caption(f"{done} of {len(rows)} closed.")
        ui.table([{"closed": "yes" if r["done"] else "no", "item": r["text"]}
                  for r in rows], height=320)
