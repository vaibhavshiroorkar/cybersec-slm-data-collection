#!/usr/bin/env python3
"""Ingest (stage 2): inspect what was fetched into data/raw/.

Read-only. Run this stage and watch the log from the Overview page; every value
here comes from :mod:`cybersec_slm.dashboard.data`.
"""

from __future__ import annotations

from collections import Counter

import streamlit as st

from cybersec_slm.dashboard import cached, charts, data, ui

ui.inject_css()
ui.page_header("ingest", data.stage_states())
st.caption("Sources fetched to `data/raw/`, one row per source. Run this stage "
           "from the Overview page; inspect what each source produced here.")

# ------------------------------------------------------------------ stats ------
raw = cached.data_funnel(data.scope())["raw"]
prog = data.ingest_progress()
raw_rows = cached.raw_table(data.scope())
rows = cached.ingest_table(data.scope())
raw_size = sum(r["size_mb"] for r in raw_rows)
with ui.section("Ingested (raw)",
                "Records are raw catalog rows (large tabular datasets dominate). "
                "Size is the real folder footprint, measured once and cached."):
    ui.stat_grid([
        ("Sources with data", charts.fmt_int(len(raw_rows))),
        ("Checked / catalog", f"{prog['checked']} / {prog['total']}"),
        ("Records", charts.fmt_int(raw["lines"])),
        ("Size on disk", charts.fmt_size(raw_size)),
    ], cols=4)

# ------------------------------------------------------ full per-source table ---
with ui.section("Every source", "The whole catalog reconciled against `data/raw/`: "
                                "what each source produced, or why it produced "
                                "nothing. Ingested sources first, then by size."):
    if not rows:
        st.caption("No `sources/Sources.csv` found yet, or it has no readable rows.")
    else:
        by_status = Counter(r["status"] for r in rows)
        ingested = by_status.get("ingested", 0)
        ui.stat_grid([
            ("Catalogued", charts.fmt_int(len(rows))),
            ("Ingested", charts.fmt_int(ingested)),
            ("License-excluded", charts.fmt_int(by_status.get("license", 0))),
            ("Fetch issues", charts.fmt_int(len(rows) - ingested
                                            - by_status.get("license", 0))),
        ], cols=4)

        status_opts = [s for s in data.INGEST_STATUSES if by_status.get(s)]
        picked = st.multiselect("Filter by status (empty = all)", status_opts,
                                key="ingest_status_filter")
        doms = sorted({r["sub-domain"] for r in rows})
        picked_doms = st.multiselect("Filter by sub-domain (empty = all)", doms,
                                     key="ingest_domain_filter")
        shown = [r for r in rows
                 if (not picked or r["status"] in picked)
                 and (not picked_doms or r["sub-domain"] in picked_doms)]
        st.caption(f"{len(shown)} of {len(rows)} sources")
        ui.table([{"source": r["source"], "name": r["name"],
                   "sub-domain": r["sub-domain"], "status": r["status"],
                   "records": r["records"], "size (MB)": round(r["size_mb"], 1),
                   "files": r["files"], "license": r["license"],
                   "reason": r["reason"]} for r in shown], height=460)

# --------------------------------------------------- sources that produced none -
with ui.section("No data (and why)",
                "Every catalogued source reconciled against `data/raw/`. Most are "
                "turned away by the commercial-license gate before download; the "
                "rest failed to fetch, timed out, or came back empty."):
    missing = [r for r in rows if r["status"] != "ingested"]
    if not missing:
        st.caption("Every catalogued source produced data.")
    else:
        by_type = Counter(r["status"] for r in missing)
        lic = by_type.get("license", 0)
        m = st.columns(3)
        m[0].metric("No data", charts.fmt_int(len(missing)))
        m[1].metric("License-excluded", charts.fmt_int(lic))
        m[2].metric("Fetch issues", charts.fmt_int(len(missing) - lic))
        ui.table(sorted(
            [{"sub-domain": r["sub-domain"], "source": r["source"],
              "type": r["status"], "reason": r["reason"]} for r in missing],
            key=lambda r: (r["type"], r["sub-domain"], r["source"])), height=420)

# ------------------------------------------------------- ingested folder table -
with ui.section("Sources on disk", "The folder tree under `data/raw/`, measured in "
                                   "bytes rather than read from the catalog."):
    if raw_rows:
        display = [{"sub-domain": r["sub-domain"], "source": r["source"],
                    "files": r["files"], "size (MB)": round(r["size_mb"], 1)}
                   for r in raw_rows]
        ui.table(display, height=460)
    else:
        st.caption("Nothing under `data/raw/` yet. Run the ingest stage above.")

