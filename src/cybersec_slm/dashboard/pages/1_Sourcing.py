#!/usr/bin/env python3
"""Sourcing (stage 1): the source catalog + a discover control.

Presentation only; every value comes from :mod:`cybersec_slm.dashboard.data` /
:mod:`cybersec_slm.dashboard.control`.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import charts, data, ui

ui.inject_css()
ui.stage_header("source", data.stage_states())
st.caption("Discover and curate sources into `sources/Sources.csv`. Discovery uses "
           "Google Programmable Search; set `GOOGLE_SEARCH_API_KEY` and "
           "`GOOGLE_SEARCH_ENGINE_ID` (env) before running it.")

ui.stage_run_control("source", run_label="Discover sources")
st.divider()

# ---------------------------------------------------------------- catalog ------
st.subheader("Source catalog")
cat = data.catalog_summary()
ui.stat_grid([
    ("Sources in catalog", charts.fmt_int(cat["total"])),
    ("Sub-domains", charts.fmt_int(len(cat["by_domain"]))),
], cols=2)

rows = [{"Sub-Domain": k, "sources": v}
        for k, v in sorted(cat["by_domain"].items(), key=lambda kv: kv[1], reverse=True)]
if rows:
    with st.container(height=360):
        st.dataframe(rows, use_container_width=True, hide_index=True)
else:
    st.caption("No `sources/Sources.csv` found yet.")

st.divider()

# ------------------------------------------------------------------- log -------
st.subheader("Stage log")


@st.fragment(run_every=3)
def _logs() -> None:
    ui.log_box(data.log_tail(200))


_logs()
