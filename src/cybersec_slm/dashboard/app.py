#!/usr/bin/env python3
"""Streamlit entrypoint - the Overview: all headline stats + the full-pipeline
launcher. Presentation only; every value comes from :mod:`data` / :mod:`control`.

Run with ``cybersec-slm dashboard`` or ``streamlit run
src/cybersec_slm/dashboard/app.py`` (after ``uv sync --extra dashboard``). Streamlit
lists the ``pages/`` scripts (one per pipeline stage, then Dataset and Agent) in the
sidebar.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm import stages
from cybersec_slm.dashboard import charts, control, data, ui

st.set_page_config(page_title="cybersec-slm dashboard", page_icon="🛡️",
                   layout="wide")
ui.inject_css()

st.title("cybersec-slm-data-collection")
st.caption(f"Reading data root: `{data.data_root()}`  ·  five-stage pipeline: "
           "source → ingest → clean → eda → schema")


# ---------------------------------------------------------------- live strip ---
@st.fragment(run_every=3)
def _live() -> None:
    """Run status + the five-stage strip. One fragment over a fixed skeleton so
    values change in place without pushing the page up or down."""
    status = data.run_status()
    running = status["state"] == "running"
    phase = status.get("phase") or {}
    t = data.run_timing()

    top = st.columns(3)
    top[0].metric("Pipeline", "● running" if running else "○ idle")
    top[1].metric("Stage", phase.get("label", "—"))
    if running and t.get("elapsed_s") is not None:
        eta = ("~" + charts.fmt_duration(t["eta_s"])) if t.get("eta_s") is not None \
            else {"finalizing": "finalizing…", "starting": "starting…"}.get(
                t.get("basis"), "—")
        top[2].metric("Elapsed / ETA",
                      f"{charts.fmt_duration(t['elapsed_s'])} / {eta}")
    else:
        top[2].metric("Last activity", charts.fmt_age(status.get("age")))

    # Five-stage chip strip: each stage's done/running/pending/failed status.
    st.markdown("**Stages**")
    states = data.stage_states()
    chips = st.columns(len(stages.STAGES))
    for i, key in enumerate(stages.stage_keys()):
        stage = stages.get_stage(key)
        chips[i].markdown(
            f"**{i + 1}. {stage.label}**  \n{ui.status_pill(states[key]['state'])}")


_live()
st.divider()


# ------------------------------------------------------------------- funnel ----
st.subheader("Corpus funnel")
funnel = data.data_funnel()
ui.stat_grid([
    ("Sources ingested", charts.fmt_int(funnel["raw"]["sources"])),
    ("Records ingested", charts.fmt_int(funnel["raw"]["lines"])),
    ("Records cleaned", charts.fmt_int(funnel["cleaned"]["lines"])),
    ("Records final", charts.fmt_int(funnel["appended"]["lines"])),
], cols=4)

# ------------------------------------------------------------------ EDA gate ---
st.subheader("EDA sufficiency gate")
eda = data.latest_eda()
if not eda:
    st.caption("No EDA run yet. Run the EDA stage.")
else:
    passed = eda.get("passed")
    viol = eda.get("violations", []) or []
    blockers = [v for v in viol if v.get("severity") == "blocker"]
    (st.success if passed else st.error)(
        f"{'✅ PASS' if passed else '❌ FAIL'}  ·  {len(blockers)} blocker(s)  ·  "
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
    st.caption("No manifest yet. Run the schema stage.")
else:
    ui.stat_grid([
        ("Records", charts.fmt_int(man.get("record_count"))),
        ("Unique hashes", charts.fmt_int(man.get("unique_content_hashes"))),
        ("Tokens", charts.fmt_int(man.get("token_total"))),
        ("Domains", charts.fmt_int(len(man.get("domains") or {}))),
    ], cols=4)

st.divider()

# ------------------------------------------------------------------ launcher ---
st.subheader("Run the full pipeline")
cstat = control.status()
running = cstat["running"]
settings = ui.advanced_settings("all")
b = st.columns(4)
if b[0].button("▶ Start", disabled=running, use_container_width=True,
               help="Run all five stages: ingest → clean → EDA → schema"):
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
               help="Delete ALL pipeline data and logs (clean slate)"):
    st.session_state["confirm_reset"] = True

if running:
    st.caption(f"● running: {cstat.get('stage') or 'pipeline'}  ·  pid {cstat['pid']}"
               f"  ·  started {cstat.get('started_at')}")
elif cstat.get("stale"):
    st.caption("Previous run ended without a clean stop.")

if st.session_state.get("confirm_reset") and not running:
    st.warning("Delete ALL pipeline data (`data/` and `logs/`)? This cannot be undone.")
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

st.caption("Controls act on the pipeline on this machine (local-first dashboard). "
           "Open a stage page in the sidebar to run or inspect a single stage.")
