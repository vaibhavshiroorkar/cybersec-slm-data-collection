#!/usr/bin/env python3
"""Streamlit entrypoint - landing/overview. Presentation only; all reads via data.

Run with ``cybersec-slm dashboard`` or
``streamlit run src/cybersec_slm/dashboard/app.py`` (after ``uv sync --extra
dashboard``). Streamlit auto-lists the ``pages/`` scripts in the sidebar.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import charts, data

st.set_page_config(page_title="cybersec-slm dashboard", page_icon="🛡️",
                   layout="wide")

st.title("cybersec-slm-data-collection")
st.caption(f"Reading data root: `{data.data_root()}`")

@st.fragment(run_every=2)
def _render_overview():
    status = data.run_status()
    prog = data.live_progress(tail=0)
    c1, c2, c3 = st.columns(3)
    if status["state"] == "running":
        c1.metric("Pipeline", "● running")
    else:
        c1.metric("Pipeline", "○ idle")
    c2.metric("Last activity", charts.fmt_age(status.get("age")))
    total = prog.get("total")
    c3.metric("Sources completed",
              f"{charts.fmt_int(prog['completed'])}"
              + (f" / {charts.fmt_int(total)}" if total else ""))

    man = data.manifest()
    if man:
        st.metric("Corpus size", f"{charts.fmt_int(man.get('record_count'))} records")

_render_overview()

st.markdown(
    """
### Where to go
- **Pipeline** - watch a run live, and review the EDA sufficiency gate, trends
  over past runs, the per-source table, stage reports, and the release manifest.
- **Dataset** - search, filter, and browse the final corpus, plus the records
  that were rejected or de-duplicated.

Select a page from the sidebar. This dashboard is **read-only**: it reflects what
the pipeline has written under the data root above.
"""
)
