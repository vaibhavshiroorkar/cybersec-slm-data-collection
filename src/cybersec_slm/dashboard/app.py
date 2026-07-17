#!/usr/bin/env python3
"""Streamlit entrypoint: the Overview control center.

Runs the whole pipeline and shows live status, the corpus funnel, and the release
headline. Presentation only; every value comes from :mod:`data` / :mod:`control`.

Run with ``cybersec-slm dashboard`` or ``streamlit run
src/cybersec_slm/dashboard/app.py`` (after ``uv sync --extra dashboard``).
"""

from __future__ import annotations

import inspect
import os
import time

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

    # "Stage N of 5" caption, shown only while a run is active. The sources-checked
    # bar that used to sit here is gone: the corpus funnel renders the same figure
    # from the same ingest_progress() a few hundred pixels below, so the Overview
    # showed one progress bar twice.
    if running:
        checked = data.ingest_progress().get("checked") or 0
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

    def _do_quick_finish() -> None:
        # Stop first: the snapshot must not race the clean pass it is snapshotting.
        # The ledger is untouched by a stop, so the resume inside the plan picks up
        # exactly where this run left off and nothing is recleaned.
        if control.status()["running"]:
            control.stop()
        res = control.start("quick-finish", settings=run_settings)
        st.rerun() if res.get("ok") else st.error(res["error"])

    def _do_eda_fix() -> None:
        # Same reason Quick finish stops first: the fix's own clean rounds must not
        # race a clean pass already in flight. The ledger survives a stop, so the
        # resume inside each round picks up exactly where this run left off.
        if control.status()["running"]:
            control.stop()
        res = control.start("eda-fix", settings=run_settings)
        st.rerun() if res.get("ok") else st.error(res["error"])

    b = st.columns(5)
    # The two multi-stage recipes live behind More: they are deliberate,
    # occasional actions, and putting them beside Start/Resume/Stop invited a
    # mis-click into a run that reorders the whole pipeline.
    with b[4].popover("More", use_container_width=True):
        st.caption("Multi-stage recipes. Each stops a run in flight first, then "
                   "resumes from its checkpoint, so nothing is refetched or "
                   "recleaned.")
        if st.button("Quick finish", key="more_quick_finish",
                     use_container_width=True,
                     help="Pause cleaning and build a dataset from what is already "
                          "cleaned: EDA (observe only) and Schema run over "
                          "data/clean as it stands, then cleaning resumes from its "
                          "checkpoint and a final EDA + Schema rebuild over the "
                          "fuller corpus. Nothing is recleaned; the snapshot's gate "
                          "never blocks the run, because a partial corpus fails it "
                          "by construction."):
            _do_quick_finish()
        if st.button("EDA fix", key="more_eda_fix", use_container_width=True,
                     help="Balance the corpus: source only the sub-domains the EDA "
                          "gate reports as starved, ingest and clean what arrives, "
                          "then look again, repeating until it balances or "
                          "discovery runs dry. Only adds data, never deletes it. "
                          "The EDA page shows what it would target."):
            _do_eda_fix()
        st.divider()
        if st.button("Test run", key="more_test_run", disabled=running,
                     use_container_width=True,
                     help="Health check after a change: seeds a small synthetic "
                          "corpus into a throwaway data root and runs clean, EDA, "
                          "schema and the schema validator over it, reporting "
                          "pass/fail per stage. It cannot touch your corpus: the "
                          "run's data root is a temp directory, so the real one is "
                          "not reachable from it. Offline, and takes seconds."):
            _res = control.start("test-run")
            st.rerun() if _res.get("ok") else st.error(_res["error"])

        _tr = control.test_report()
        if _tr:
            _mark = "passed" if _tr.get("ok") else "FAILED"
            _bad = [s["step"] for s in _tr.get("steps", []) if not s["ok"]]
            (st.success if _tr.get("ok") else st.error)(
                f"Last test run {_mark} in {_tr.get('seconds')}s"
                + (f"  ·  broke at: {', '.join(_bad)}" if _bad else "")
                + f"  ·  {_tr.get('ts', '')}")
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
def _data_funnel_snapshot(measure_size: bool = True) -> dict:
    """Call the dashboard data funnel with compatibility for legacy signatures."""
    data_funnel = getattr(data, "data_funnel", None)
    if not callable(data_funnel):
        return {}

    try:
        sig = inspect.signature(data_funnel)
    except (TypeError, ValueError):
        return data_funnel()

    accepts_measure_size = any(
        p.name == "measure_size" for p in sig.parameters.values()
    )
    accepts_var_kw = any(
        p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
    )
    if accepts_measure_size or accepts_var_kw:
        return data_funnel(measure_size=measure_size)
    return data_funnel()


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
    funnel = _data_funnel_snapshot(measure_size=False)
    _root = data.data_root()
    funnel["raw"]["size_mb"] = cached.raw_size_mb(_root)
    # Raw records are counted on disk, not read off the catalog, whose Total Lines
    # understated the live corpus by 149% and knew nothing of 242 fetched sources.
    # Same treatment as Size: too costly for a 1s tick, so it comes from the
    # long-TTL cached count.
    funnel["raw"]["lines"] = cached.raw_records(_root)
    # Cleaned records grow live as clean workers write; the clean report only lands
    # when the pass finishes, so read the on-disk count (cached, short TTL) instead.
    funnel["cleaned"]["lines"] = cached.cleaned_records(_root)
    # Same treatment for the final dataset, which grows live as normalize appends
    # and whose manifest only lands when the pass finishes. Reading it from the
    # manifest showed 0 records beside a multi-GB Size for the whole run.
    funnel["appended"].update(cached.final_stats(_root))
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


# --------------------------------------------------------- stage activity ------
def _timeline_chart(rows: list[dict]):
    """Gantt of stage activity: stages on y, minutes since the run began on x."""
    import altair as alt

    order = [r["stage"] for r in rows]          # pipeline order, not alphabetical
    base = alt.Chart(alt.Data(values=rows))
    bars = base.mark_bar(cornerRadius=4, height=14).encode(
        x=alt.X("start_min:Q", title="Minutes since the run began",
                axis=alt.Axis(grid=True, gridOpacity=0.15, domain=False,
                              tickColor="#52514e", labelColor="#c3c2b7",
                              titleColor="#c3c2b7")),
        x2="end_min:Q",
        y=alt.Y("stage:N", title=None, sort=order,
                axis=alt.Axis(grid=False, domain=False, ticks=False,
                              labelColor="#c3c2b7", labelFontSize=12)),
        color=alt.Color("state:N", title="Stage",
                        scale=alt.Scale(domain=list(charts.TIMELINE_STATES),
                                        range=[charts.TIMELINE_DONE_COLOR,
                                               charts.TIMELINE_RUNNING_COLOR]),
                        legend=alt.Legend(orient="top", direction="horizontal",
                                          labelColor="#c3c2b7",
                                          titleColor="#c3c2b7")),
        tooltip=[alt.Tooltip("stage:N", title="Stage"),
                 alt.Tooltip("state:N", title="State"),
                 alt.Tooltip("duration:N", title="Duration"),
                 alt.Tooltip("start_min:Q", title="Started (min)", format=".1f")],
    )
    # Direct label per bar: five bars is few enough to label every one, and it
    # keeps duration readable without a hover (and off the colour alone).
    labels = base.mark_text(align="left", dx=6, fontSize=11,
                            color="#c3c2b7").encode(
        x=alt.X("end_min:Q"), y=alt.Y("stage:N", sort=order), text="duration:N")
    return (bars + labels).properties(height=28 * len(rows) + 40).configure_view(
        strokeWidth=0).configure_legend(labelFontSize=11, titleFontSize=11)


@st.fragment(run_every=5)
def _stage_activity() -> None:
    """Live stage activity, refreshed every 5s.

    Slower than the funnel's 1s tick on purpose: this reads the run's whole log
    and only changes when a stage boundary is crossed, which is minutes apart.
    """
    rows = charts.stage_timeline_rows(data.stage_timeline())
    if not rows:
        st.caption("No stage activity yet. Start a run from the panel above.")
        return
    st.altair_chart(_timeline_chart(rows), use_container_width=True)
    st.caption("Each bar spans from when a stage first logged to when the next "
               "one began; the running stage extends to now. Stages a resumed "
               "plan skipped never logged, so they are absent rather than empty.")


# Rendered near the bottom (just above the gate + release row) — the timeline is
# history, read after the live strip, funnel, and log rather than before them.

# ------------------------------------------------------------- live throughput --
def _rate_chart(rows: list[dict], unit: str):
    """Per-second throughput of the live stage: one series, no legend."""
    import altair as alt

    base = alt.Chart(alt.Data(values=rows))
    line = base.mark_line(strokeWidth=2, color=charts.LIVE_RATE_COLOR,
                          interpolate="monotone").encode(
        x=alt.X("elapsed_s:Q", title="Seconds watched",
                axis=alt.Axis(grid=True, gridOpacity=0.15, domain=False,
                              tickColor="#52514e", labelColor="#c3c2b7",
                              titleColor="#c3c2b7")),
        y=alt.Y("rate:Q", title=f"{unit}/s",
                axis=alt.Axis(grid=True, gridOpacity=0.15, domain=False,
                              tickColor="#52514e", labelColor="#c3c2b7",
                              titleColor="#c3c2b7")),
    )
    # Crosshair + tooltip: a line chart is read by pointing at it.
    hover = alt.selection_point(nearest=True, on="pointerover",
                                fields=["elapsed_s"], empty=False)
    points = base.mark_point(size=60, opacity=0, color=charts.LIVE_RATE_COLOR).encode(
        x=alt.X("elapsed_s:Q"), y=alt.Y("rate:Q"),
        tooltip=[alt.Tooltip("rate:Q", title=f"{unit}/s", format=".2f"),
                 alt.Tooltip("elapsed_s:Q", title="Seconds watched", format=".0f")],
    ).add_params(hover)
    rule = base.mark_rule(color="#52514e").encode(x="elapsed_s:Q").transform_filter(hover)
    return (line + rule + points).properties(height=180).configure_view(strokeWidth=0)


@st.fragment(run_every=1)
def _live_rate() -> None:
    """The live stage's throughput, sampled once a second.

    One slot that follows the run: the metric is whatever the current stage
    actually moves (see data.stage_progress_sample), so the chart re-scales and
    relabels itself at a stage boundary instead of the page growing a chart per
    stage. Samples are per browser session and reset when the run's pid changes,
    because a rate carried across two different runs is not a rate.
    """
    sample = data.stage_progress_sample()
    if sample is None:
        st.caption("No live stage to chart. The throughput graph follows the "
                   "running stage.")
        return

    pid = data.run_status().get("pid")
    buf = st.session_state.get("_rate_buf")
    if not buf or buf.get("pid") != pid or buf.get("stage") != sample["stage"]:
        buf = {"pid": pid, "stage": sample["stage"], "samples": []}
    buf["samples"] = (buf["samples"] +
                      [{"t": time.time(), "value": sample["value"]}])[-300:]
    st.session_state["_rate_buf"] = buf

    rows = charts.live_rate_rows(buf["samples"])
    if len(rows) < 2:
        st.caption(f"Sampling {sample['label']} ({sample['what']})… the rate needs "
                   "a few seconds of history.")
        return
    st.altair_chart(_rate_chart(rows, sample["unit"]), use_container_width=True)
    latest = rows[-1]["rate"]
    st.caption(f"{sample['label']}  ·  {sample['what']}  ·  now "
               f"{latest:,.2f} {sample['unit']}/s  ·  last {len(rows)}s")


with ui.section("Live throughput",
                "How fast the current stage is moving, sampled every second."):
    _live_rate()

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

# --------------------------------------------------------- stage activity ------
with ui.section("Stage activity",
                "Which stage the run has been in, over time."):
    _stage_activity()

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
        # Records, Tokens and Size come from the dataset on disk, not the manifest:
        # normalize only writes the manifest when a whole pass finishes, so during a
        # run (and after an interrupted one) these read zero beside a multi-GB file.
        # Unique hashes stays on the manifest, which is the only thing that counts
        # them, and so is absent until the pass completes.
        _rel = cached.final_stats(data.data_root())
        if not _rel["lines"] and not man:
            st.caption("No dataset yet. Run the pipeline to reach the schema stage.")
        else:
            ui.stat_grid([
                ("Records", charts.fmt_int(_rel["lines"])),
                ("Unique hashes", charts.fmt_int(man.get("unique_content_hashes"))
                                  if man else "n/a"),
                ("Tokens", charts.fmt_int(_rel["tokens"])),
                ("Size", charts.fmt_size(_rel["size_mb"])),
            ], cols=2)
