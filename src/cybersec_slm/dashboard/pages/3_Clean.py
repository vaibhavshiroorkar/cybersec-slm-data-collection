#!/usr/bin/env python3
"""Clean (stage 3): clean data/raw/ + cross-source dedup -> data/clean/.

Presentation only; every value comes from :mod:`cybersec_slm.dashboard.data` /
:mod:`cybersec_slm.dashboard.control`.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import charts, data, ui

ui.inject_css()
ui.stage_header("clean", data.stage_states())
st.caption("Clean every fetched source and cross-source deduplicate into "
           "`data/clean/`. Deletes `data/raw/` afterward unless *keep raw*.")

ui.stage_run_control("clean")
st.divider()

# ------------------------------------------------------------------ stats ------
st.subheader("Cleaned")
funnel = data.data_funnel()
cleaned = funnel["cleaned"]
raw_in = funnel["raw"]["lines"] or None
delta = (cleaned["lines"] - raw_in) if raw_in else None
c = st.columns(3)
c[0].metric("Sources", charts.fmt_int(cleaned["sources"]))
c[1].metric("Records out", charts.fmt_int(cleaned["lines"]),
            delta=charts.fmt_int(delta) if delta else None)
c[2].metric("Size", f"{cleaned['size_mb']:.1f} MB")

rc = data.clean_report()
if rc.get("total"):
    t = rc["total"]
    with st.expander("Cleaning breakdown"):
        st.write({k: t.get(k) for k in
                  ("in", "out", "struct_dropped", "behavioral_flagged",
                   "exact_dups", "near_dups", "pii_redacted", "translated",
                   "non_en_dropped") if k in t})

st.divider()

# ---------------------------------------------------------- where data went ----
st.subheader("Where did my data go?")
lb = data.loss_breakdown()
active = [s for s in lb["stages"] if s["dropped"] > 0]
if not active and not lb["per_source"]:
    st.caption("No clean report yet - run the clean stage to see the drop breakdown.")
else:
    lc = st.columns(3)
    lc[0].metric("Raw records in", charts.fmt_int(lb["raw_in"]))
    lc[1].metric("After cleaning", charts.fmt_int(lb["clean_out"]))
    lc[2].metric("In final dataset", charts.fmt_int(lb["final_written"]))

    st.markdown("**Dropped by mechanism** (biggest first)")
    ranked = sorted(active, key=lambda s: s["dropped"], reverse=True)
    with st.container(height=260):
        st.dataframe(
            [{"stage": s["stage"], "mechanism": s["mechanism"],
              "records dropped": s["dropped"], "kind": s["kind"]} for s in ranked],
            use_container_width=True, hide_index=True)

    st.markdown("**Per-source losses** (biggest first)")
    with st.container(height=300):
        rows = lb["per_source"]
        if rows:
            st.dataframe(
                [{"source": r["source"], "sub-domain": r["sub_domain"],
                  "in": r["in"], "out": r["out"], "kept %": r["kept_pct"],
                  "lost": r["lost"], "top reason": r["top_drop_reason"]}
                 for r in rows[:200]],
                use_container_width=True, hide_index=True)
        else:
            st.caption("No per-source clean rows yet.")

st.divider()

# ------------------------------------------------------------------- log -------
st.subheader("Stage log")


@st.fragment(run_every=3)
def _logs() -> None:
    ui.log_box(data.log_tail(200))


_logs()
