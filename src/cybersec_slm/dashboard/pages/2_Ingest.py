#!/usr/bin/env python3
"""Ingest (stage 2): inspect what was fetched into data/raw/.

Read-only. Run this stage and watch the log from the Overview page; every value
here comes from :mod:`cybersec_slm.dashboard.data`.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import cached, charts, data, ui

ui.inject_css()
ui.stage_header("ingest", data.stage_states())
st.caption("Sources fetched to `data/raw/`. The table below maps the folder tree "
           "on disk, one row per source.")
st.divider()

# ------------------------------------------------------------------ stats ------
st.subheader("Ingested (raw)")
raw = data.data_funnel()["raw"]
prog = data.ingest_progress()
raw_rows = cached.raw_table(data.data_root())
raw_size = sum(r["size_mb"] for r in raw_rows)
ui.stat_grid([
    ("Sources with data", charts.fmt_int(len(raw_rows))),
    ("Checked / catalog", f"{prog['checked']} / {prog['total']}"),
    ("Records", charts.fmt_int(raw["lines"])),
    ("Size on disk", charts.fmt_size(raw_size)),
], cols=4)
st.caption("Records are raw rows from the catalog (large tabular datasets "
           "dominate). Size is the real folder footprint, measured once and cached.")

st.divider()

# ------------------------------------------------------- ingested folder table -
st.subheader("Ingested sources (data/raw)")
if raw_rows:
    display = [{"sub-domain": r["sub-domain"], "source": r["source"],
                "files": r["files"], "size (MB)": round(r["size_mb"], 1)}
               for r in raw_rows]
    ui.table(display, height=460)
else:
    st.caption("Nothing under `data/raw/` yet. Run the ingest stage from the "
               "Overview page.")

st.divider()

# --------------------------------------------------- sources that produced none -
st.subheader("Sources with no data (and why)")
st.caption("Every catalogued source, reconciled against `data/raw/`. This lists "
           "each one that produced no records, with the reason. Most are turned "
           "away by the commercial-license gate before download; the rest failed "
           "to fetch, timed out, or came back empty.")
missing = data.sources_without_data()
if not missing:
    st.caption("Every catalogued source produced data.")
else:
    from collections import Counter
    by_type = Counter(r["type"] for r in missing)
    lic = by_type.get("license", 0)
    fetch_issues = len(missing) - lic
    m = st.columns(3)
    m[0].metric("No data", charts.fmt_int(len(missing)))
    m[1].metric("License-excluded", charts.fmt_int(lic))
    m[2].metric("Fetch issues", charts.fmt_int(fetch_issues))
    ui.table([{"sub-domain": r["sub-domain"], "source": r["source"],
               "type": r["type"], "reason": r["reason"]} for r in missing],
             height=420)
