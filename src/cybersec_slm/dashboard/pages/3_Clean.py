#!/usr/bin/env python3
"""Clean (stage 3): inspect the cleaned corpus under data/clean/.

Read-only. Run this stage and watch the log from the Overview page; every value
here comes from :mod:`cybersec_slm.dashboard.data`.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import charts, data, ui

ui.inject_css()
ui.stage_header("clean", data.stage_states())
st.caption("Cleaned and cross-source deduplicated records under `data/clean/`.")
st.divider()

# ------------------------------------------------------------------ stats ------
st.subheader("Cleaned")
funnel = data.data_funnel()
cleaned = funnel["cleaned"]
c = st.columns(3)
c[0].metric("Sources", charts.fmt_int(cleaned["sources"]))
c[1].metric("Records", charts.fmt_int(cleaned["lines"]))
c[2].metric("Size", charts.fmt_size(cleaned["size_mb"]))

rc = data.clean_report()
if rc.get("total"):
    t = rc["total"]
    with st.expander("Cleaning breakdown"):
        st.write({k: t.get(k) for k in
                  ("in", "out", "struct_dropped", "behavioral_flagged",
                   "exact_dups", "near_dups", "pii_redacted", "translated",
                   "non_en_dropped") if k in t})

st.divider()

# ----------------------------------------------------------- cleaned table -----
st.subheader("Cleaned sources")
ct = data.cleaned_table()
if ct:
    st.caption(f"{len(ct)} sources under `data/clean/`.")
    ui.table(ct, height=340)
else:
    st.caption("Nothing cleaned yet. Run the clean stage from the Overview page.")

st.divider()

# ---------------------------------------------------------- where data went ----
st.subheader("Where did my data go?")
lb = data.loss_breakdown()
active = [s for s in lb["stages"] if s["dropped"] > 0]
if not active and not lb["per_source"]:
    st.caption("No clean report yet. Run the clean stage to see the drop breakdown.")
else:
    lc = st.columns(3)
    lc[0].metric("Raw records in", charts.fmt_int(lb["raw_in"]))
    lc[1].metric("After cleaning", charts.fmt_int(lb["clean_out"]))
    lc[2].metric("In final dataset", charts.fmt_int(lb["final_written"]))

    st.markdown("**Dropped by mechanism** (biggest first)")
    ranked = sorted(active, key=lambda s: s["dropped"], reverse=True)
    ui.table(
        [{"stage": s["stage"], "mechanism": s["mechanism"],
          "records dropped": s["dropped"], "kind": s["kind"]} for s in ranked],
        height=260)

    st.markdown("**Per-source losses** (biggest first)")
    rows = lb["per_source"]
    if rows:
        ui.table(
            [{"source": r["source"], "sub-domain": r["sub_domain"],
              "in": r["in"], "out": r["out"], "kept %": r["kept_pct"],
              "lost": r["lost"], "top reason": r["top_drop_reason"]}
             for r in rows[:200]], height=300)
    else:
        st.caption("No per-source clean rows yet.")
