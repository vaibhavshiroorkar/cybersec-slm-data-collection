#!/usr/bin/env python3
"""Sourcing (stage 1): inspect the source catalog.

Read-only. Running a stage and watching the log both live on the Overview page;
every value here comes from :mod:`cybersec_slm.dashboard.data`.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import charts, data, ui

ui.inject_css()
ui.stage_header("source", data.stage_states())
st.caption("The curated source catalog in `sources/Sources.csv`. Discovery runs "
           "from the Overview page; this page shows what is catalogued.")
st.divider()

# ---------------------------------------------------------------- catalog ------
st.subheader("Source catalog")
cat = data.catalog_summary()
ui.stat_grid([
    ("Sources in catalog", charts.fmt_int(cat["total"])),
    ("Sub-domains", charts.fmt_int(len(cat["by_domain"]))),
], cols=2)

st.markdown("**By sub-domain**")
by_dom = [{"sub-domain": k, "sources": v}
          for k, v in sorted(cat["by_domain"].items(), key=lambda kv: kv[1], reverse=True)]
if by_dom:
    ui.table(by_dom, height=280)
else:
    st.caption("No `sources/Sources.csv` found yet.")

st.divider()

# --------------------------------------------------------------- full table ----
st.subheader("Sources.csv")
rows = data.catalog_rows()
if not rows:
    st.caption("No `sources/Sources.csv` found yet.")
else:
    st.caption(f"{len(rows)} rows")
    ui.table(rows, height=460)
