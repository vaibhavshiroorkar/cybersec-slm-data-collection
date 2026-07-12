#!/usr/bin/env python3
"""Streamlit entrypoint: the Overview control center.

Runs the whole pipeline and shows live status, the corpus funnel, and the release
headline. Presentation only; every value comes from :mod:`data` / :mod:`control`.

Run with ``cybersec-slm dashboard`` or ``streamlit run
src/cybersec_slm/dashboard/app.py`` (after ``uv sync --extra dashboard``).
"""

from __future__ import annotations

import os

import streamlit as st

from cybersec_slm.dashboard import cached, charts, control, data, ui

st.set_page_config(page_title="cybersec-slm dashboard", page_icon="🛡️",
                   layout="wide")
ui.inject_css()

st.title("cybersec-slm-data-collection")
st.caption(f"Reading data root: `{data.data_root()}`")
st.caption("Run the whole pipeline here and watch its status, log, and headline "
           "stats. Open a stage page in the sidebar to inspect one stage in detail.")


# ---------------------------------------------------------------- live strip ---
@st.fragment(run_every=3)
def _live() -> None:
    """Run status: state, current stage, elapsed / last activity."""
    status = data.run_status()
    running = status["state"] == "running"
    phase = status.get("phase") or {}
    t = data.run_timing()

    top = st.columns(3)
    top[0].metric("Pipeline", "● running" if running else "○ idle")
    top[1].metric("Stage", phase.get("label", "n/a"))
    if running and t.get("elapsed_s") is not None:
        top[2].metric("Elapsed", charts.fmt_duration(t["elapsed_s"]))
    else:
        top[2].metric("Last activity", charts.fmt_age(status.get("age")))


_live()
st.divider()

# ------------------------------------------------------------------ launcher ---
st.subheader("Run the full pipeline")
cstat = control.status()
running = cstat["running"]
settings = ui.advanced_settings("all")
b = st.columns(4)
if b[0].button("▶ Start", disabled=running, use_container_width=True,
               help="Run all stages: ingest, clean, EDA, schema"):
    res = control.start("all", settings=settings)
    st.rerun() if res.get("ok") else st.error(res["error"])
if b[1].button("⏵ Resume", disabled=running, use_container_width=True,
               help="Continue a prior run, skipping sources already fetched"):
    res = control.start("all", resume=True, settings=settings)
    st.rerun() if res.get("ok") else st.error(res["error"])
if b[2].button("⏹ Stop", disabled=not running, use_container_width=True):
    control.stop()
    st.rerun()
if b[3].button("🗑 Reset", disabled=running, use_container_width=True,
               help="Delete all pipeline data and logs (clean slate)"):
    st.session_state["confirm_reset"] = True

if running:
    st.caption(f"running: {cstat.get('stage') or 'pipeline'}  ·  session (pid) "
               f"{cstat['pid']}  ·  started {cstat.get('started_at')}")
elif cstat.get("stale"):
    st.caption("Previous run ended without a clean stop.")
else:
    st.caption("Auto-rebalance is off by default (enable it in Advanced settings). "
               "Raw files are kept after cleaning. Controls act on this machine.")

if st.session_state.get("confirm_reset") and not running:
    st.warning("Delete all pipeline data (`data/` and `logs/`)? This cannot be undone.")
    r = st.columns(2)
    if r[0].button("Yes, delete everything", type="primary", use_container_width=True):
        res = control.reset()
        st.session_state["confirm_reset"] = False
        if not res.get("ok"):
            st.error(res["error"])
        st.rerun()
    if r[1].button("Cancel", use_container_width=True):
        st.session_state["confirm_reset"] = False
        st.rerun()

st.divider()

# ---------------------------------------------------------------- pipeline log -
st.subheader("Pipeline log")
_sess = data.run_status()
if _sess.get("newest_log"):
    st.caption(f"session (pid) `{_sess.get('pid') or '?'}`  ·  log file "
               f"`logs/{os.path.basename(_sess['newest_log'])}`")


@st.fragment(run_every=3)
def _pipeline_log() -> None:
    ui.log_box(data.log_tail(200))


_pipeline_log()

# ---------------------------------------------------------------- sessions -----
with st.expander("Session history"):
    hist = data.session_history()
    if hist:
        ui.table([{"session (pid)": h["pid"], "log file": h["log"],
                   "started": h["started"],
                   "last activity": charts.fmt_age(h["age_s"]),
                   "size": charts.fmt_size(h["size_kb"] / 1024),
                   "current": "●" if h["current"] else ""} for h in hist])
    else:
        st.caption("No pipeline sessions yet.")

st.divider()

# ------------------------------------------------------------------- funnel ----
st.subheader("Corpus funnel")
funnel = data.data_funnel()
prog = data.ingest_progress()
funnel["raw"]["size_mb"] = cached.raw_size_mb(data.data_root())

pct = (prog["checked"] / prog["total"]) if prog["total"] else 0.0
st.progress(min(pct, 1.0),
            text=f"Sources checked: {prog['checked']} of {prog['total']} "
                 f"({pct * 100:.0f}%)  ·  {prog['with_data']} produced data")


def _funnel_row(label: str, d: dict) -> None:
    """One funnel stage as a labelled Sources / Records / Size row."""
    c = st.columns([1.6, 1, 1, 1])
    c[0].markdown(f"**{label}**")
    c[1].metric("Sources", charts.fmt_int(d["sources"]))
    c[2].metric("Records", charts.fmt_int(d["lines"]))
    c[3].metric("Size", charts.fmt_size(d["size_mb"]))


_funnel_row("Ingested (raw)", funnel["raw"])
_funnel_row("Cleaned", funnel["cleaned"])
_funnel_row("Final dataset", funnel["appended"])
st.caption("Records are raw rows, so large tabular datasets dominate the ingested "
           "count. Raw size is the real folder footprint (measured once, cached). "
           "See the Ingest page for the per-source breakdown, including sources "
           "that produced no data.")

st.divider()

# ------------------------------------------------------------------ EDA gate ---
st.subheader("EDA sufficiency gate")
eda = data.latest_eda()
if not eda:
    st.caption("No EDA run yet. Run the pipeline to reach the EDA stage.")
else:
    passed = eda.get("passed")
    viol = eda.get("violations", []) or []
    blockers = [v for v in viol if v.get("severity") == "blocker"]
    (st.success if passed else st.error)(
        f"{'PASS' if passed else 'FAIL'}  ·  {len(blockers)} blocker(s)  ·  "
        f"{eda.get('ts', '')}")
    m = eda.get("metrics", {}) or {}
    ui.stat_grid([
        ("Records", charts.fmt_int(m.get("total"))),
        ("Subdomains", charts.fmt_int(m.get("num_subdomains"))),
        ("Dup rate", charts.fmt_pct(m.get("dup_rate"))),
        ("Avg tokens", charts.fmt_int((m.get("text_quality") or {}).get("avg_tokens"))),
    ], cols=4)

# ------------------------------------------------------------------ manifest ---
st.subheader("Release")
man = data.manifest()
if not man:
    st.caption("No manifest yet. Run the pipeline to reach the schema stage.")
else:
    ui.stat_grid([
        ("Records", charts.fmt_int(man.get("record_count"))),
        ("Unique hashes", charts.fmt_int(man.get("unique_content_hashes"))),
        ("Tokens", charts.fmt_int(man.get("token_total"))),
        ("Domains", charts.fmt_int(len(man.get("domains") or {}))),
    ], cols=4)
