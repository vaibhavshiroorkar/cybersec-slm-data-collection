#!/usr/bin/env python3
"""Pipeline page - monitor a run (live) + review the EDA gate, trends, reports.

Presentation only; every value comes from :mod:`cybersec_slm.dashboard.data`.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import charts, control, data

st.title("Pipeline")

# ----------------------------------------------------------------- controls ----
def _render_controls() -> None:
    cstat = control.status()
    running = cstat["running"]
    b1, b2, b3, b4 = st.columns(4)
    if b1.button("▶ Start", disabled=running, use_container_width=True,
                 help="Run the full pipeline: ingest → clean → dedup → EDA → normalize"):
        res = control.start(resume=False)
        if res.get("ok"):
            st.rerun()
        else:
            st.error(res["error"])
    if b2.button("⏵ Resume", disabled=running, use_container_width=True,
                 help="Continue a prior run, skipping sources already completed"):
        res = control.start(resume=True)
        if res.get("ok"):
            st.rerun()
        else:
            st.error(res["error"])
    if b3.button("⏹ Stop", disabled=not running, use_container_width=True,
                 help="Kill the run now (sources already finished are kept)"):
        control.stop()
        st.rerun()
    if b4.button("🗑 Reset", disabled=running, use_container_width=True,
                 help="Delete ALL pipeline data and logs (clean slate)"):
        st.session_state["confirm_reset"] = True

    if running:
        st.caption(f"● running · pid {cstat['pid']} · started {cstat.get('started_at')}")
    elif cstat.get("stale"):
        st.caption("Previous run ended without a clean stop.")

    if st.session_state.get("confirm_reset") and not running:
        st.warning("Delete ALL pipeline data (`data/` and `logs/`)? This cannot be undone.")
        r1, r2 = st.columns(2)
        if r1.button("Yes, delete everything", type="primary", use_container_width=True):
            res = control.reset()
            st.session_state["confirm_reset"] = False
            if not res.get("ok"):
                st.error(res["error"])
            st.rerun()
        if r2.button("Cancel", use_container_width=True):
            st.session_state["confirm_reset"] = False
            st.rerun()

    st.caption("Controls act on the pipeline on this machine (local-first dashboard).")

st.subheader("Controls")
_render_controls()
st.divider()

# --------------------------------------------------------------- live monitor --
_PHASE_ICON = {"ingest_clean": "📥", "dedup": "🧬", "eda": "🧪",
               "normalize": "📦", "done": "✅", "gate_failed": "⛔",
               "starting": "⏳", "unknown": "○"}


def _render_live() -> None:
    status = data.run_status()
    prog = data.live_progress(tail=40)
    running = status["state"] == "running"
    phase = status.get("phase") or {}
    pkey = phase.get("phase", "unknown")

    cols = st.columns(4)
    cols[0].metric("State", "● running" if running else "○ idle")
    # Phase: what stage the run is in now, or (when idle) the last run's outcome.
    icon = _PHASE_ICON.get(pkey, "•")
    step = (f"{phase.get('index')}/{phase.get('total')}"
            if running and phase.get("index") else None)
    cols[1].metric("Phase" if running else "Last phase",
                   f"{icon} {phase.get('label', '—')}",
                   delta=(f"step {step}" if step else None), delta_color="off")
    total = prog.get("total")
    cols[2].metric("Sources checked",
                   f"{prog['completed']}" + (f" / {total}" if total else ""))
    cols[3].metric("Last activity", charts.fmt_age(status.get("age")))

    # Time since the run started + a rough estimate of time remaining. The ETA is
    # a linear projection from sources completed and only shown during ingest (the
    # source-count-driven phase); the tail shows "finalizing" instead of a number.
    if running:
        t = data.run_timing()
        if t.get("elapsed_s") is not None:
            tcol = st.columns(2)
            tcol[0].metric("Elapsed", charts.fmt_duration(t["elapsed_s"]))
            if t.get("eta_s") is not None:
                tcol[1].metric("Est. remaining", "~" + charts.fmt_duration(t["eta_s"]),
                               help="Rough linear estimate from sources completed; "
                                    "sources vary widely in size, so treat as approximate.")
            else:
                tcol[1].metric("Est. remaining",
                               {"finalizing": "finalizing…", "starting": "starting…"}
                               .get(t.get("basis"), "—"))

    # Phase progress bar over the 5-stage spine (ingest→dedup→eda→normalize→done).
    if phase.get("total") and pkey not in ("unknown", "starting"):
        frac = min((phase.get("index", 0)) / phase["total"], 1.0)
        if pkey == "gate_failed":
            st.progress(frac, text="Halted at EDA gate — address blockers below and re-run")
        else:
            st.progress(frac, text=phase.get("label", ""))
    # Within the ingest phase, the per-source ledger is the finer-grained bar.
    if running and pkey == "ingest_clean" and total:
        st.progress(min(prog["completed"] / total, 1.0),
                    text=f"{prog['completed']} / {total} sources checked")
    if phase.get("detail"):
        st.caption(f"↳ {phase['detail']}")

    tail = prog.get("log_tail") or []
    if tail:
        st.code("\n".join(tail), language="log")
    else:
        st.caption("No pipeline log yet - start a run with `cybersec-slm run`.")

st.subheader("Run status")
if data.run_status()["state"] == "running":
    st.fragment(_render_live, run_every=3)()   # live strip re-runs ~every 3s
else:
    if st.button("↻ Refresh"):
        st.rerun()
    _render_live()

st.divider()

# ------------------------------------------------------------- data funnel ---
st.subheader("Data Funnel")

@st.fragment(run_every=2)
def _render_funnel():
    funnel = data.data_funnel()
    rc = data.clean_report()
    nr = data.normalize_report()

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("### Raw")
        st.metric("Sources", charts.fmt_int(funnel['raw']['sources']))
        st.metric("Records in", charts.fmt_int(funnel['raw']['lines']))
        st.metric("Size", f"{funnel['raw']['size_mb']:.1f} MB")

    with col2:
        st.markdown("### Cleaned")
        st.metric("Sources", charts.fmt_int(funnel['cleaned']['sources']))
        raw_in = funnel['raw']['lines'] or None
        delta_clean = (funnel['cleaned']['lines'] - raw_in) if raw_in else None
        st.metric("Records out", charts.fmt_int(funnel['cleaned']['lines']),
                  delta=charts.fmt_int(delta_clean) if delta_clean else None)
        st.metric("Size", f"{funnel['cleaned']['size_mb']:.1f} MB")

        with st.expander("Cleaning breakdown"):
            if rc.get("total"):
                t = rc["total"]
                st.write({k: t.get(k) for k in
                          ("in", "out", "struct_dropped", "behavioral_flagged",
                           "exact_dups", "near_dups", "pii_redacted", "translated",
                           "non_en_dropped") if k in t})
            else:
                st.caption("No clean report yet.")

    with col3:
        st.markdown("### Final")
        st.metric("Sources", charts.fmt_int(funnel['appended']['sources']))
        cleaned_out = funnel['cleaned']['lines'] or None
        delta_final = (funnel['appended']['lines'] - cleaned_out) if cleaned_out else None
        st.metric("Records written", charts.fmt_int(funnel['appended']['lines']),
                  delta=charts.fmt_int(delta_final) if delta_final else None)
        st.metric("Size", f"{funnel['appended']['size_mb']:.1f} MB")

        ap = funnel['appended']
        lost_synthetic = ap.get('synthetic_excluded', 0)
        lost_dups = ap.get('near_dups', 0) + ap.get('exact_dups', 0)
        lost_rejected = ap.get('rejected', 0)
        if lost_synthetic or lost_dups or lost_rejected:
            with st.expander("Why records were dropped"):
                st.write({
                    "synthetic excluded": lost_synthetic,
                    "near/exact dups": lost_dups,
                    "schema rejected": lost_rejected,
                })
        with st.expander("Normalization breakdown"):
            if nr:
                st.write(nr.get("counts", {}))
                if nr.get("paused_sources"):
                    st.warning(f"paused sources: {', '.join(nr['paused_sources'])}")
            else:
                st.caption("No normalize report yet.")

_render_funnel()

st.divider()

# ------------------------------------------------------------- data loss view --
st.subheader("Where did my data go?")

lb = data.loss_breakdown()
_active_stages = [s for s in lb["stages"] if s["dropped"] > 0]
if not _active_stages and not lb["per_source"]:
    st.caption("No clean report yet - run the pipeline to see the drop breakdown.")
else:
    lc = st.columns(3)
    lc[0].metric("Raw records in", charts.fmt_int(lb["raw_in"]))
    lc[1].metric("After cleaning", charts.fmt_int(lb["clean_out"]))
    lc[2].metric("In final dataset", charts.fmt_int(lb["final_written"]))

    st.markdown("**Dropped by mechanism** (biggest first)")
    _ranked = sorted(_active_stages, key=lambda s: s["dropped"], reverse=True)
    st.dataframe(
        [{"stage": s["stage"], "mechanism": s["mechanism"],
          "records dropped": s["dropped"], "kind": s["kind"]} for s in _ranked],
        use_container_width=True, hide_index=True)

    with st.expander("Per-source losses (biggest first)"):
        _rows = lb["per_source"]
        if _rows:
            st.dataframe(
                [{"source": r["source"], "sub-domain": r["sub_domain"],
                  "in": r["in"], "out": r["out"], "kept %": r["kept_pct"],
                  "lost": r["lost"], "top reason": r["top_drop_reason"]}
                 for r in _rows[:200]],
                use_container_width=True, hide_index=True)
        else:
            st.caption("No per-source clean rows yet.")

    st.caption("‘no prose column’ = feature/label tables with no natural-language "
               "field (URL lists, numeric features, hashes, hex vectors); a format "
               "exclusion, not a quality drop. Watch the mitre-attack rows: those "
               "are genuine text that may be recoverable.")

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
    g = st.columns(7)
    g[0].metric("Records", charts.fmt_int(m.get("total")))
    g[1].metric("Subdomains", charts.fmt_int(m.get("num_subdomains")))
    g[2].metric("Worst src share", charts.fmt_pct(conc.get("worst_share")))
    g[3].metric("Dup rate", charts.fmt_pct(m.get("dup_rate")))
    g[4].metric("Avg tokens", charts.fmt_int(q.get("avg_tokens")))
    g[5].metric("Drift", charts.fmt_pct(drift.get("max_delta")))
    g[6].metric("Topic CV", f"{m.get('topic_cv', 0.0):.2f}")

    feedback = eda.get("feedback", {})
    if feedback.get("recommendations"):
        st.markdown("**Actionable Feedback (V2 Topic Balance)**")
        for rec in feedback["recommendations"]:
            st.info(f"💡 {rec}")

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
st.subheader("Sources Table")

@st.fragment(run_every=2)
def _render_sources_table():
    srcs = data.source_table()
    if srcs:
        st.dataframe(srcs, use_container_width=True, hide_index=True)
    else:
        st.caption("No source table yet (`logs/final_table.csv` is written at run end).")

_render_sources_table()

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
