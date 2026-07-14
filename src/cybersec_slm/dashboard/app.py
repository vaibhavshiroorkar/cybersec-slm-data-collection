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

from cybersec_slm.dashboard import cached, charts, control, data, settings_store, ui

st.set_page_config(page_title="cybersec-slm dashboard", layout="wide")
ui.inject_css()

ui.app_header("cybersec-slm-data-collection")
st.caption(f"Reading data root: `{data.data_root()}`  ·  run the whole pipeline "
           "here; open a stage in the sidebar to inspect it in detail.")


# ---------------------------------------------------------------- live strip ---
@st.fragment(run_every=3)
def _live() -> None:
    """Run status: state, current stage, elapsed / last activity."""
    status = data.run_status()
    running = status["state"] == "running"
    phase = status.get("phase") or {}
    t = data.run_timing()

    top = st.columns(3)
    top[0].metric("Pipeline", "running" if running else "idle")
    top[1].metric("Stage", phase.get("label", "n/a"))
    if running and t.get("elapsed_s") is not None:
        top[2].metric("Elapsed", charts.fmt_duration(t["elapsed_s"]))
    else:
        top[2].metric("Last activity", charts.fmt_age(status.get("age")))


with ui.section("Run status"):
    _live()

# ------------------------------------------------------------------ launcher ---
with ui.section("Run the full pipeline"):
    cstat = control.status()
    running = cstat["running"]
    # Seed the panel from settings saved on the stage pages, so a value configured
    # (and saved) on the Ingest/Clean/EDA page also drives the full run. Any flag
    # `all` does not accept is dropped by build_command.
    _saved_all = settings_store.merged_all()
    settings = ui.advanced_settings("all", defaults=_saved_all)
    run_settings = {**_saved_all, **settings}   # saved fills gaps; live panel wins
    b = st.columns(4)
    if b[0].button("Start", disabled=running, use_container_width=True,
                   help="Run all stages: ingest, clean, EDA, schema"):
        res = control.start("all", settings=run_settings)
        st.rerun() if res.get("ok") else st.error(res["error"])
    if b[1].button("Resume", disabled=running, use_container_width=True,
                   help="Continue a prior run, skipping sources already fetched"):
        res = control.start("all", resume=True, settings=run_settings)
        st.rerun() if res.get("ok") else st.error(res["error"])
    if b[2].button("Stop", disabled=not running, use_container_width=True):
        control.stop()
        st.rerun()
    if b[3].button("Reset", disabled=running, use_container_width=True,
                   help="Instantly delete the entire data/ folder and logs"):
        res = control.reset()
        if not res.get("ok"):
            st.error(res["error"])
        else:
            removed = ", ".join(res.get("removed") or []) or "nothing"
            skipped = res.get("skipped") or []
            msg = f"Reset: cleared {removed}."
            if skipped:
                msg += f" {len(skipped)} file(s) in use kept (e.g. the active log)."
            st.toast(msg)
        st.rerun()

    if running:
        st.caption(f"running: {cstat.get('stage') or 'pipeline'}  ·  session (pid) "
                   f"{cstat['pid']}  ·  started {cstat.get('started_at')}")
    elif cstat.get("stale"):
        st.caption("Previous run ended without a clean stop.")
    else:
        st.caption("Reset instantly deletes the data/ folder (no confirmation). "
                   "Auto-rebalance is off by default; raw files are kept after "
                   "cleaning. Controls act on this machine.")

# ------------------------------------------------------------------- funnel ----
# Cached: the funnel scans data/ on every rerun, which made the Overview reload on
# each interaction. It renders from a cached snapshot; Refresh (or a run) clears it.
def _funnel_row(label: str, d: dict) -> None:
    """One funnel stage as a labelled Sources / Records / Size row."""
    c = st.columns([1.6, 1, 1, 1])
    c[0].markdown(f"**{label}**")
    c[1].metric("Sources", charts.fmt_int(d["sources"]))
    c[2].metric("Records", charts.fmt_int(d["lines"]))
    c[3].metric("Size", charts.fmt_size(d["size_mb"]))


with ui.section("Corpus funnel",
                "Records are raw rows, so large tabular datasets dominate the "
                "ingested count. Cached for ~90s; see the Ingest page for the "
                "per-source breakdown."):
    if st.button("Refresh", key="funnel_refresh",
                 help="Remeasure data/ now (otherwise cached for ~90s)"):
        cached.clear_stats()
        st.rerun()
    _snap = cached.funnel(data.data_root())
    funnel = _snap["funnel"]
    prog = _snap["progress"]
    pct = (prog["checked"] / prog["total"]) if prog["total"] else 0.0
    st.progress(min(pct, 1.0),
                text=f"Sources checked: {prog['checked']} of {prog['total']} "
                     f"({pct * 100:.0f}%)  ·  {prog['with_data']} produced data")
    _funnel_row("Ingested (raw)", funnel["raw"])
    _funnel_row("Cleaned", funnel["cleaned"])
    _funnel_row("Final dataset", funnel["appended"])

# ---------------------------------------------------------------- pipeline log -
_sess = data.run_status()


@st.fragment(run_every=3)
def _pipeline_log() -> None:
    ui.log_box(data.log_tail(200))


with ui.section("Pipeline log"):
    if _sess.get("newest_log"):
        st.caption(f"session (pid) `{_sess.get('pid') or '?'}`  ·  log file "
                   f"`logs/{os.path.basename(_sess['newest_log'])}`")
    _pipeline_log()

    with st.expander("Session history"):
        hist = data.session_history()
        if hist:
            ui.table([{"session (pid)": h["pid"], "log file": h["log"],
                       "started": h["started"],
                       "last activity": charts.fmt_age(h["age_s"]),
                       "size": charts.fmt_size(h["size_kb"] / 1024),
                       "current": "yes" if h["current"] else ""} for h in hist])
        else:
            st.caption("No pipeline sessions yet.")

# ------------------------------------------------------------ gate + release ---
eda = data.latest_eda()
man = data.manifest()
left, right = st.columns(2)

with left:
    with ui.section("EDA sufficiency gate"):
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
                ("Avg tokens",
                 charts.fmt_int((m.get("text_quality") or {}).get("avg_tokens"))),
            ], cols=2)

with right:
    with ui.section("Release"):
        if not man:
            st.caption("No manifest yet. Run the pipeline to reach the schema stage.")
        else:
            ui.stat_grid([
                ("Records", charts.fmt_int(man.get("record_count"))),
                ("Unique hashes", charts.fmt_int(man.get("unique_content_hashes"))),
                ("Tokens", charts.fmt_int(man.get("token_total"))),
                ("Domains", charts.fmt_int(len(man.get("domains") or {}))),
            ], cols=2)
