#!/usr/bin/env python3
"""Pipeline page — monitor a run (live) + review the EDA gate, trends, reports.

Presentation only; every value comes from :mod:`cybersec_slm.dashboard.data`.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import charts, data

st.title("Pipeline")


# --------------------------------------------------------------- live monitor --
def _render_live() -> None:
    status = data.run_status()
    prog = data.live_progress(tail=40)
    running = status["state"] == "running"

    cols = st.columns(3)
    cols[0].metric("State", "● running" if running else "○ idle")
    total = prog.get("total")
    cols[1].metric("Sources completed",
                   f"{prog['completed']}" + (f" / {total}" if total else ""))
    cols[2].metric("Last activity", charts.fmt_age(status.get("age")))
    if total:
        st.progress(min(prog["completed"] / total, 1.0) if total else 0.0)

    tail = prog.get("log_tail") or []
    if tail:
        st.code("\n".join(tail), language="log")
    else:
        st.caption("No pipeline log yet — start a run with `cybersec-slm run`.")


st.subheader("Run status")
if data.run_status()["state"] == "running":
    st.fragment(_render_live, run_every=3)()   # live strip re-runs ~every 3s
else:
    if st.button("↻ Refresh"):
        st.rerun()
    _render_live()

st.divider()

# ------------------------------------------------------------------- EDA gate --
st.subheader("EDA sufficiency gate")
eda = data.latest_eda()
if not eda:
    st.info("No EDA run yet (`logs/eda/latest.json` absent). Run `cybersec-slm eda`.")
else:
    passed = eda.get("passed")
    violations = eda.get("violations", []) or []
    blockers = [v for v in violations if v.get("severity") == "blocker"]
    warnings = [v for v in violations if v.get("severity") == "warning"]
    (st.success if passed else st.error)(
        f"{'✅ PASS' if passed else '❌ FAIL'} — {len(blockers)} blocker(s), "
        f"{len(warnings)} warning(s)   ·   {eda.get('ts', '')}")
    for v in blockers:
        st.error(f"blocker [{v['check']}]: {v['message']}")
    for v in warnings:
        st.warning(f"warning [{v['check']}]: {v['message']}")

    m = eda.get("metrics", {}) or {}
    q = m.get("text_quality", {}) or {}
    conc = m.get("concentration", {}) or {}
    drift = m.get("drift", {}) or {}
    g = st.columns(6)
    g[0].metric("Records", charts.fmt_int(m.get("total")))
    g[1].metric("Subdomains", charts.fmt_int(m.get("num_subdomains")))
    g[2].metric("Worst src share", charts.fmt_pct(conc.get("worst_share")))
    g[3].metric("Dup rate", charts.fmt_pct(m.get("dup_rate")))
    g[4].metric("Avg tokens", charts.fmt_int(q.get("avg_tokens")))
    g[5].metric("Drift", charts.fmt_pct(drift.get("max_delta")))

st.divider()

# --------------------------------------------------------------------- trends --
st.subheader("Trends (across past runs)")
rows = charts.eda_trend_rows(data.eda_history())
if len(rows) < 2:
    st.caption("Need at least two EDA runs to chart trends.")
else:
    st.line_chart({"total records": [r["total"] for r in rows]})
    st.line_chart({"dup rate": [r["dup_rate"] for r in rows],
                   "drift": [r["drift"] for r in rows]})

st.divider()

# -------------------------------------------------------------- sources table --
st.subheader("Sources")
srcs = data.source_table()
if srcs:
    st.dataframe(srcs, use_container_width=True, hide_index=True)
else:
    st.caption("No source table yet (`logs/final_table.csv` is written at run end).")

st.divider()

# ------------------------------------------------------------- stage reports ---
st.subheader("Stage reports")
rc = data.clean_report()
nr = data.normalize_report()
c1, c2 = st.columns(2)
with c1:
    st.markdown("**Cleaning**")
    if rc.get("total"):
        t = rc["total"]
        st.write({k: t.get(k) for k in
                  ("in", "out", "struct_dropped", "behavioral_flagged",
                   "exact_dups", "near_dups", "pii_redacted", "translated",
                   "non_en_dropped") if k in t})
    else:
        st.caption("No clean report yet.")
with c2:
    st.markdown("**Normalization**")
    if nr:
        st.write(nr.get("counts", {}))
        if nr.get("paused_sources"):
            st.warning(f"paused sources: {', '.join(nr['paused_sources'])}")
    else:
        st.caption("No normalize report yet.")

st.divider()

# ------------------------------------------------------------------ manifest ---
st.subheader("Release manifest")
man = data.manifest()
if not man:
    st.caption("No manifest yet (`data/final/manifest.json`). Run `cybersec-slm normalize`.")
else:
    m1, m2, m3 = st.columns(3)
    m1.metric("Records", charts.fmt_int(man.get("record_count")))
    m2.metric("Unique hashes", charts.fmt_int(man.get("unique_content_hashes")))
    m3.metric("Tokens", charts.fmt_int(man.get("token_total")))
    st.caption(f"pipeline {man.get('pipeline_version')} · git "
               f"{(man.get('git_commit') or '')[:10]} · sha256 "
               f"{(man.get('dataset_sha256') or '')[:12]}…")
    d1, d2 = st.columns(2)
    d1.markdown("**By domain**"); d1.write(man.get("domains", {}))
    d2.markdown("**By license**"); d2.write(man.get("licenses", {}))
