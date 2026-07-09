#!/usr/bin/env python3
"""Pipeline page - monitor a run (live) + review the EDA gate, trends, reports.

Presentation only; every value comes from :mod:`cybersec_slm.dashboard.data`.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import charts, data, theme, viz

st.set_page_config(page_title="Pipeline · cybersec-slm", page_icon="🛡️", layout="wide")
theme.inject()

_status = data.run_status()
_running = _status["state"] == "running"
theme.hero(
    "Pipeline", "monitor · gate · reports",
    "live run state, the sufficiency gate, and the raw → cleaned → final funnel",
    theme.pill("running" if _running else "idle",
               "signal" if _running else "muted", live=_running))


# --------------------------------------------------------------- live monitor --
def _render_live() -> None:
    status = data.run_status()
    prog = data.live_progress(tail=40)
    running = status["state"] == "running"
    total = prog.get("total")
    theme.kpi_grid([
        {"label": "state", "value": "running" if running else "idle",
         "status": "signal" if running else "muted"},
        {"label": "sources completed",
         "value": f'{prog["completed"]}' + (f'/{total}' if total else ""),
         "status": "signal", "sub": "of catalog" if total else None},
        {"label": "last activity", "value": charts.fmt_age(status.get("age")),
         "status": "muted"},
    ])
    if total:
        st.progress(min(prog["completed"] / total, 1.0))
    tail = prog.get("log_tail") or []
    if tail:
        st.code("\n".join(tail), language="log")
    else:
        st.caption("No pipeline log yet - start a run with `cybersec-slm run`.")


theme.section("Run status", eyebrow="live")
if _running:
    st.fragment(_render_live, run_every=3)()
else:
    if st.button("↻ Refresh"):
        st.rerun()
    _render_live()


# ----------------------------------------------------------------- data funnel --
theme.section("Data funnel", eyebrow="raw → cleaned → final",
              desc="records surviving each stage")


@st.fragment(run_every=3)
def _render_funnel() -> None:
    funnel = data.data_funnel()
    rc = data.clean_report()
    nr = data.normalize_report()
    raw, cln, fin = funnel["raw"], funnel["cleaned"], funnel["appended"]

    theme.kpi_grid([
        {"label": "raw records", "value": charts.fmt_int(raw["lines"]),
         "unit": f'· {raw["sources"]} src', "status": "muted"},
        {"label": "cleaned records", "value": charts.fmt_int(cln["lines"]),
         "unit": f'· {cln["sources"]} src', "status": "signal"},
        {"label": "final records", "value": charts.fmt_int(fin["lines"]),
         "unit": f'· {fin["sources"]} src', "status": "pass"},
        {"label": "final size", "value": f'{fin["size_mb"]:.1f}', "unit": "MB",
         "status": "accent"},
    ])

    chart = viz.funnel_bar([
        {"stage": "Raw", "lines": raw["lines"]},
        {"stage": "Cleaned", "lines": cln["lines"]},
        {"stage": "Final", "lines": fin["lines"]},
    ])
    if chart is not None:
        st.altair_chart(chart, use_container_width=True)

    c1, c2 = st.columns(2)
    with c1, st.expander("Cleaning breakdown"):
        if rc.get("total"):
            t = rc["total"]
            st.write({k: t.get(k) for k in
                      ("in", "out", "struct_dropped", "behavioral_flagged",
                       "exact_dups", "near_dups", "pii_redacted", "translated",
                       "non_en_dropped") if k in t})
        else:
            st.caption("No clean report yet.")
    with c2, st.expander("Normalization breakdown"):
        if nr:
            st.write(nr.get("counts", {}))
            if nr.get("paused_sources"):
                st.warning(f"paused sources: {', '.join(nr['paused_sources'])}")
        else:
            st.caption("No normalize report yet.")


_render_funnel()


# ------------------------------------------------------------------- EDA gate --
theme.section("EDA sufficiency gate", eyebrow="quality gate",
              desc="whether the corpus is balanced and clean enough to release")
eda = data.latest_eda()
if not eda:
    st.info("No EDA run yet (`logs/eda/latest.json` absent). Run `cybersec-slm eda`.")
else:
    passed = eda.get("passed")
    violations = eda.get("violations", []) or []
    blockers = [v for v in violations if v.get("severity") == "blocker"]
    warnings = [v for v in violations if v.get("severity") == "warning"]
    st.markdown(
        theme.pill(f'{"PASS" if passed else "FAIL"} · {len(blockers)} blocker(s) · '
                   f'{len(warnings)} warning(s)',
                   theme.status_of("gate", passed))
        + f'<span class="pill" style="margin-left:8px">{eda.get("ts", "")}</span>',
        unsafe_allow_html=True)
    for v in blockers:
        st.error(f"blocker [{v['check']}]: {v['message']}")
    for v in warnings:
        st.warning(f"warning [{v['check']}]: {v['message']}")

    m = eda.get("metrics", {}) or {}
    q = m.get("text_quality", {}) or {}
    conc = m.get("concentration", {}) or {}
    drift = m.get("drift", {}) or {}
    theme.kpi_grid([
        {"label": "records", "value": charts.fmt_int(m.get("total"))},
        {"label": "subdomains", "value": charts.fmt_int(m.get("num_subdomains")),
         "status": "accent"},
        {"label": "worst src share", "value": charts.fmt_pct(conc.get("worst_share")),
         "status": "warn"},
        {"label": "dup rate", "value": charts.fmt_pct(m.get("dup_rate")), "status": "warn"},
        {"label": "avg tokens", "value": charts.fmt_int(q.get("avg_tokens"))},
        {"label": "drift", "value": charts.fmt_pct(drift.get("max_delta")), "status": "warn"},
        {"label": "topic cv", "value": f'{m.get("topic_cv", 0.0):.2f}', "status": "accent"},
    ])
    feedback = eda.get("feedback", {})
    for rec in (feedback.get("recommendations") or []):
        st.info(f"💡 {rec}")


# --------------------------------------------------------------------- trends --
theme.section("Trends", eyebrow="across past runs",
              desc="how the corpus has evolved run over run")
rows = charts.eda_trend_rows(data.eda_history())
if len(rows) < 2:
    st.caption("Need at least two EDA runs to chart trends.")
else:
    c1, c2 = st.columns(2)
    with c1:
        st.caption("total records")
        st.altair_chart(viz.trend_lines(rows, [("total", "records")]),
                        use_container_width=True)
    with c2:
        st.caption("dup rate & drift")
        st.altair_chart(viz.trend_lines(rows, [("dup_rate", "dup rate"),
                                               ("drift", "drift")]),
                        use_container_width=True)


# -------------------------------------------------------------- sources table --
theme.section("Sources", eyebrow="per-source outcome",
              desc="written to `logs/final_table.csv` at run end")


@st.fragment(run_every=3)
def _render_sources_table() -> None:
    srcs = data.source_table()
    if srcs:
        st.dataframe(srcs, use_container_width=True, hide_index=True)
    else:
        st.caption("No source table yet (`logs/final_table.csv` is written at run end).")


_render_sources_table()


# ------------------------------------------------------------------ manifest ---
theme.section("Release manifest", eyebrow="datasheet",
              desc="the signed summary of the released corpus")
man = data.manifest()
if not man:
    st.caption("No manifest yet (`data/final/manifest.json`). Run `cybersec-slm normalize`.")
else:
    theme.kpi_grid([
        {"label": "records", "value": charts.fmt_int(man.get("record_count")),
         "status": "pass"},
        {"label": "unique hashes", "value": charts.fmt_int(man.get("unique_content_hashes"))},
        {"label": "tokens", "value": charts.fmt_int(man.get("token_total")), "status": "accent"},
    ])
    st.caption(f"pipeline {man.get('pipeline_version')} · git "
               f"{(man.get('git_commit') or '')[:10]} · sha256 "
               f"{(man.get('dataset_sha256') or '')[:12]}…")
    d1, d2 = st.columns(2)
    d1.markdown("**By subdomain**"); d1.write(man.get("subdomains", {}))
    d2.markdown("**By license**"); d2.write(man.get("licenses", {}))
