#!/usr/bin/env python3
"""Ingest (stage 2): fetch all sources to data/raw/. Fetch-only, no cleaning.

Presentation only; every value comes from :mod:`cybersec_slm.dashboard.data` /
:mod:`cybersec_slm.dashboard.control`.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import charts, data, ui

ui.inject_css()
ui.stage_header("ingest", data.stage_states())
st.caption("Fetch every catalogued source to `data/raw/` (license + light-EDA gate "
           "applied). Raw is retained for the clean stage.")

ui.stage_run_control("ingest")
st.divider()

# ------------------------------------------------------------------ stats ------
st.subheader("Ingested (raw)")
raw = data.data_funnel()["raw"]
ui.stat_grid([
    ("Sources", charts.fmt_int(raw["sources"])),
    ("Records", charts.fmt_int(raw["lines"])),
    ("Size", f"{raw['size_mb']:.1f} MB"),
], cols=3)

st.divider()

# ---------------------------------------------------------------- ledger -------
st.subheader("Per-source ingest ledger")


@st.fragment(run_every=3)
def _ledger() -> None:
    srcs = data.source_table()
    if srcs:
        with st.container(height=360):
            st.dataframe(srcs, use_container_width=True, hide_index=True)
    else:
        st.caption("No source table yet (`logs/final_table.csv` is written at run end).")


_ledger()

st.divider()

# ------------------------------------------------------------------- log -------
st.subheader("Stage log")


@st.fragment(run_every=3)
def _logs() -> None:
    ui.log_box(data.log_tail(200))


_logs()
