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

from cybersec_slm import stages
from cybersec_slm.dashboard import cached, charts, control, data, ui

st.set_page_config(page_title="cybersec-slm dashboard", layout="wide")
ui.inject_css()

ui.app_header("cybersec-slm-data-collection")


# ---------------------------------------------------------------- live strip ---
@st.fragment(run_every=1)
def _live() -> None:
    """Run status: state, current stage, elapsed, ETA + a live sources progress bar.

    Re-runs every 1s (the fragment decorator), so the bar and ETA advance during a
    run without reflowing the rest of the page. Every value is read from ``data``;
    nothing here computes state.
    """
    status = data.run_status()
    running = status["state"] == "running"
    phase = status.get("phase") or {}
    t = data.run_timing()

    top = st.columns(4)
    top[0].metric("Pipeline", "running" if running else "idle")
    top[1].metric("Stage", phase.get("label", "n/a"))
    if running and t.get("elapsed_s") is not None:
        top[2].metric("Elapsed", charts.fmt_duration(t["elapsed_s"]))
    else:
        top[2].metric("Last activity", charts.fmt_age(status.get("age")))
    # Projected total start-to-end runtime (HH:MM:SS). Only has a real number
    # during ingest; otherwise name the tail stage instead of inventing a duration.
    if running and t.get("total_s") is not None:
        top[3].metric("Est. total", charts.fmt_hms(t["total_s"]),
                      help="Projected full run time (start to finish), estimated "
                           "from the ingest rate so far. Sources vary in size, so "
                           "it settles as the run progresses.")
    else:
        _basis = {"finalizing": "finalizing", "starting": "starting",
                  "finished": "done"}.get(t.get("basis"), "—")
        top[3].metric("Est. total", _basis if running else "—")

    # Live sources bar + "Stage N of 5" caption, shown only while a run is active.
    if running:
        ip = data.ingest_progress()
        total = ip.get("total") or 0
        checked = ip.get("checked") or 0
        pct = (checked / total) if total else 0.0
        st.progress(min(pct, 1.0),
                    text=f"Ingest  ·  {charts.fmt_int(checked)} / "
                         f"{charts.fmt_int(total)} sources ({pct * 100:.0f}%)"
                         if total else
                         f"Ingest  ·  {charts.fmt_int(checked)} sources")
        idx, tot = phase.get("index"), phase.get("total")
        if idx and tot:
            st.caption(f"Stage {idx} of {tot}  ·  {phase.get('label', '')}")

        # Rolling history of sources-checked is tracked in session state
        # for future diagnostics or replay, but the Overview page does not
        # render it as a chart.
        pid = status.get("pid")
        hist = st.session_state.get("_live_history")
        if not hist or hist.get("pid") != pid:
            hist = {"pid": pid, "checked": []}
        hist["checked"] = (hist["checked"] + [checked])[-600:]
        st.session_state["_live_history"] = hist


with ui.section("Run status"):
    _live()

# ------------------------------------------------------------------ launcher ---
with ui.section("Run the full pipeline"):
    cstat = control.status()
    running = cstat["running"]
    # The full run executes source -> ingest -> clean -> eda -> schema in order,
    # each stage built entirely from its own page's saved settings (control.
    # build_full_plan); build_command drops any flag a given stage does not accept.
    # Settings live only on each stage's own page now -- this panel is run/monitor
    # only, so the stage toggles below are the only per-run choice made here.
    stage_keys = stages.stage_keys()
    stage_labels = ["Sourcing", "Ingest", "Clean", "EDA", "Schema"]

    # Connected pill toggle bar: lit = will run this launch, dimmed = skipped. All
    # five lit by default (the full pipeline).
    selected_labels = st.pills(
        "Stages to run", stage_labels, selection_mode="multi",
        default=stage_labels, key="overview_stage_pills",
        help="Lit = will run this launch. Dimmed = skipped.")
    selected_keys = {k for k, label in zip(stage_keys, stage_labels, strict=True)
                     if label in selected_labels}
    run_settings = {f"skip_{k}": True for k in stage_keys if k not in selected_keys}

    # Per-stage configuration. Each stage's link-style button opens a modal that
    # configures everything that stage's run accepts; the settings are saved per
    # stage and feed the full run below (control.build_full_plan). These are
    # rendered as borderless (tertiary) buttons so they read as settings links,
    # clearly distinct from the Start / Resume / Stop / Reset run actions below.
    st.caption("Configure a stage (saved per stage, used by the run below):")
    cfg_cols = st.columns(len(stage_keys))
    for _col, _key, _label in zip(cfg_cols, stage_keys, stage_labels, strict=True):
        if _col.button(f"Configure {_label}", key=f"cfg_{_key}", type="tertiary",
                       use_container_width=True,
                       help=f"Open {_label} run settings"):
            ui.stage_config_dialog(_key)

    # Surface the resume ledger so saved progress is visible. Neither Start nor
    # Resume wipes it now (only Reset does), so this is purely informational.
    ckpt = data.checkpoint_status()
    if not running and ckpt["exists"]:
        _saved = charts.fmt_int(ckpt["completed"])
        _tot = f"/{charts.fmt_int(ckpt['total'])}" if ckpt.get("total") else ""
        st.success(f"Checkpoint: {_saved}{_tot} sources fetched  ·  "
                   'Start and Resume both keep it; only "Reset" clears it.')

    def _do_start() -> None:
        # Start runs the lit stages without wiping: resume is passed through to the
        # stages so ingest/clean skip work already done (no re-fetch from zero, no
        # checkpoint wipe). Sourcing still runs when lit. A from-scratch rebuild is
        # reached via Reset, which clears data/ first.
        res = control.start("all", settings={**run_settings, "resume": True})
        st.rerun() if res.get("ok") else st.error(res["error"])

    b = st.columns(4)
    if b[0].button("Start", disabled=running, use_container_width=True,
                   help="Run the lit stages in order, keeping existing data: "
                        "ingest and clean skip sources already fetched/cleaned, so "
                        "it never re-fetches from zero or wipes the checkpoint. "
                        "Each stage uses the settings saved in its Configure modal. "
                        "Use Reset for a from-scratch rebuild."):
        _do_start()
    if b[1].button("Resume", disabled=running, use_container_width=True,
                   help="Continue an interrupted run from its checkpoint: skips "
                        "Sourcing discovery and resumes ingest from where it "
                        "stopped, skipping sources already fetched."):
        res = control.start("all", resume=True, settings=run_settings)
        st.rerun() if res.get("ok") else st.error(res["error"])
    if b[2].button("Stop", disabled=not running, use_container_width=True):
        control.stop()
        st.rerun()

    def _do_reset() -> None:
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

    if b[3].button("Reset", disabled=running, use_container_width=True,
                   help="Permanently delete the entire data/ folder and logs "
                        "(asks to confirm first)"):
        st.session_state["_confirm_reset"] = True
        st.rerun()
    if st.session_state.get("_confirm_reset") and not running:
        st.warning("This permanently deletes the entire data/ folder and logs. "
                   "This cannot be undone.")
        rc = st.columns(4)
        if rc[0].button("Yes, reset", use_container_width=True):
            st.session_state["_confirm_reset"] = False
            _do_reset()
        if rc[1].button("Cancel", use_container_width=True, key="cancel_reset"):
            st.session_state["_confirm_reset"] = False
            st.rerun()

    if running:
        st.caption(f"running: {cstat.get('stage') or 'pipeline'}  ·  session (pid) "
                   f"{cstat['pid']}  ·  started {cstat.get('started_at')}")
    elif cstat.get("stale"):
        st.caption("Previous run ended without a clean stop.")
    else:
        st.caption("Reset asks to confirm, then deletes the entire data/ folder.")

# ------------------------------------------------------------------- funnel ----
def _funnel_row(label: str, d: dict) -> None:
    """One funnel stage as a labelled Sources / Records / Size row."""
    c = st.columns([1.6, 1, 1, 1])
    c[0].markdown(f"**{label}**")
    c[1].metric("Sources", charts.fmt_int(d["sources"]))
    c[2].metric("Records", charts.fmt_int(d["lines"]))
    c[3].metric("Size", charts.fmt_size(d["size_mb"]))


@st.fragment(run_every=1)
def _corpus_funnel() -> None:
    """Live corpus funnel, refreshed every second in its own fragment.

    Uses the cheap counts path (``data_funnel(measure_size=False)``) for live
    source/record counts: the per-record JSONL scan and the raw ``os.walk`` are
    skipped, so each tick is a few directory listings and small reads. The raw
    Size is the one figure that needs a disk walk (raw is large), so it is pulled
    from the cached measurement (:func:`cached.raw_size_mb`, a single ~1h-TTL walk
    shared with the raw-table pages) instead of the catalog estimate, so it
    reflects what is actually on disk. Because it is a fragment, it updates without
    reflowing the rest of the page.
    """
    funnel = data.data_funnel(measure_size=False)
    _root = data.data_root()
    funnel["raw"]["size_mb"] = cached.raw_size_mb(_root)
    # Cleaned records grow live as clean workers write; the clean report only lands
    # when the pass finishes, so read the on-disk count (cached, short TTL) instead.
    funnel["cleaned"]["lines"] = cached.cleaned_records(_root)
    prog = data.ingest_progress()
    pct = (prog["checked"] / prog["total"]) if prog["total"] else 0.0
    st.progress(min(pct, 1.0),
                text=f"Sources checked: {prog['checked']} of {prog['total']} "
                     f"({pct * 100:.0f}%)  ·  {prog['with_data']} produced data")
    _funnel_row("Ingested (raw)", funnel["raw"])
    _funnel_row("Cleaned", funnel["cleaned"])
    _funnel_row("Final dataset", funnel["appended"])


with ui.section("Corpus funnel"):
    _corpus_funnel()

# ---------------------------------------------------------------- pipeline log -
_sess = data.run_status()


@st.fragment(run_every=1)
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
