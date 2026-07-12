#!/usr/bin/env python3
"""EDA (stage 4): the sufficiency gate over data/clean/, plus trends + feedback.

Presentation only; every value comes from :mod:`cybersec_slm.dashboard.data` /
:mod:`cybersec_slm.dashboard.control`.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import charts, data, ui

ui.inject_css()
ui.stage_header("eda", data.stage_states())
st.caption("Validate the cleaned corpus against the sufficiency gate. A blocker "
           "halts the full pipeline; re-run after adding or rebalancing data.")

ui.stage_run_control("eda", run_label="Re-run EDA")
st.divider()

# --------------------------------------------------------------- gate ----------
st.subheader("Sufficiency gate")
eda = data.latest_eda()
if not eda:
    st.info("No EDA run yet (`logs/eda/latest.json` absent). Run this stage.")
else:
    passed = eda.get("passed")
    violations = eda.get("violations", []) or []
    blockers = [v for v in violations if v.get("severity") == "blocker"]
    warnings = [v for v in violations if v.get("severity") == "warning"]
    (st.success if passed else st.error)(
        f"{'✅ PASS' if passed else '❌ FAIL'} - {len(blockers)} blocker(s), "
        f"{len(warnings)} warning(s)   ·   {eda.get('ts', '')}")
    for v in blockers:
        st.error(f"blocker [{v['check']}]: {v['message']}")
    for v in warnings:
        st.warning(f"warning [{v['check']}]: {v['message']}")

    m = eda.get("metrics", {}) or {}
    q = m.get("text_quality", {}) or {}
    conc = m.get("concentration", {}) or {}
    drift = m.get("drift", {}) or {}
    ui.stat_grid([
        ("Records", charts.fmt_int(m.get("total"))),
        ("Subdomains", charts.fmt_int(m.get("num_subdomains"))),
        ("Worst src share", charts.fmt_pct(conc.get("worst_share"))),
        ("Dup rate", charts.fmt_pct(m.get("dup_rate"))),
        ("Avg tokens", charts.fmt_int(q.get("avg_tokens"))),
        ("Drift", charts.fmt_pct(drift.get("max_delta"))),
        ("Topic CV", f"{m.get('topic_cv', 0.0):.2f}"),
    ], cols=4)

    feedback = eda.get("feedback", {}) or {}
    if feedback.get("recommendations"):
        st.markdown("**Actionable feedback (topic balance)**")
        for rec in feedback["recommendations"]:
            st.info(f"💡 {rec}")

st.divider()

# --------------------------------------------------------------- trends --------
st.subheader("Trends (across past runs)")
rows = charts.eda_trend_rows(data.eda_history())
if len(rows) < 2:
    st.caption("Need at least two EDA runs to chart trends.")
else:
    st.line_chart({"total records": [r["total"] for r in rows]})
    st.line_chart({"dup rate": [r["dup_rate"] for r in rows],
                   "drift": [r["drift"] for r in rows]})

st.divider()

# ------------------------------------------------------------------- log -------
st.subheader("Stage log")


@st.fragment(run_every=3)
def _logs() -> None:
    ui.log_box(data.log_tail(200))


_logs()
