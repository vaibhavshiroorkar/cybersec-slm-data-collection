#!/usr/bin/env python3
"""Schema (stage 5): normalize data/clean/ -> data/final/dataset.jsonl + manifest.

Presentation only; every value comes from :mod:`cybersec_slm.dashboard.data` /
:mod:`cybersec_slm.dashboard.control`.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import charts, data, ui

ui.inject_css()
ui.stage_header("schema", data.stage_states())
st.caption("Map cleaned records onto the canonical schema and write the release "
           "dataset + provenance manifest.")

ui.stage_run_control("schema", run_label="Re-run normalize")
st.divider()

# ---------------------------------------------------------- normalize report ---
st.subheader("Normalization")
funnel = data.data_funnel()
appended = funnel["appended"]
cleaned_out = funnel["cleaned"]["lines"] or None
delta = (appended["lines"] - cleaned_out) if cleaned_out else None
c = st.columns(3)
c[0].metric("Sources", charts.fmt_int(appended["sources"]))
c[1].metric("Records written", charts.fmt_int(appended["lines"]),
            delta=charts.fmt_int(delta) if delta else None)
c[2].metric("Size", f"{appended['size_mb']:.1f} MB")

nr = data.normalize_report()
if nr:
    with st.expander("Normalization breakdown"):
        st.write(nr.get("counts", {}))
        if nr.get("paused_sources"):
            st.warning(f"paused sources: {', '.join(nr['paused_sources'])}")
else:
    st.caption("No normalize report yet.")

st.divider()

# ------------------------------------------------------------- manifest --------
st.subheader("Release manifest")
man = data.manifest()
if not man:
    st.caption("No manifest yet (`data/final/manifest.json`). Run this stage.")
else:
    ui.stat_grid([
        ("Records", charts.fmt_int(man.get("record_count"))),
        ("Unique hashes", charts.fmt_int(man.get("unique_content_hashes"))),
        ("Tokens", charts.fmt_int(man.get("token_total"))),
    ], cols=3)
    st.caption(f"pipeline {man.get('pipeline_version')} · git "
               f"{(man.get('git_commit') or '')[:10]} · sha256 "
               f"{(man.get('dataset_sha256') or '')[:12]}…")
    d = st.columns(2)
    d[0].markdown("**By domain**")
    d[0].write(man.get("domains", {}))
    d[1].markdown("**By license**")
    d[1].write(man.get("licenses", {}))

st.divider()

# ------------------------------------------------------------------- log -------
st.subheader("Stage log")


@st.fragment(run_every=3)
def _logs() -> None:
    ui.log_box(data.log_tail(200))


_logs()
