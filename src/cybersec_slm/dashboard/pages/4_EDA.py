#!/usr/bin/env python3
"""EDA (stage 4): the sufficiency gate over data/clean/, plus metrics and trends.

Read-only. Re-run EDA and watch the log from the Overview page; every value here
comes from :mod:`cybersec_slm.dashboard.data`.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import charts, control, data, rebalance, ui

ui.inject_css()
ui.page_header("eda", data.stage_states())
st.caption("The cleaned corpus checked against the sufficiency gate. A blocker "
           "halts the full pipeline until data is added or rebalanced. Run this "
           "stage from the Overview page.")

# --------------------------------------------------------------- gate ----------
eda = data.latest_eda()
with ui.section("Sufficiency gate"):
    if not eda:
        st.info("No EDA run yet (`logs/eda/latest.json` absent). Run this stage "
                "above.")
    else:
        passed = eda.get("passed")
        violations = eda.get("violations", []) or []
        blockers = [v for v in violations if v.get("severity") == "blocker"]
        warnings = [v for v in violations if v.get("severity") == "warning"]
        (st.success if passed else st.error)(
            f"{'PASS' if passed else 'FAIL'}  ·  {len(blockers)} blocker(s), "
            f"{len(warnings)} warning(s)  ·  {eda.get('ts', '')}")
        for v in blockers:
            st.error(f"blocker [{v['check']}]: {v['message']}")
        for v in warnings:
            st.warning(f"warning [{v['check']}]: {v['message']}")

if eda:
    m = eda.get("metrics", {}) or {}
    q = m.get("text_quality", {}) or {}
    conc = m.get("concentration", {}) or {}
    drift = m.get("drift", {}) or {}
    with ui.section("Metrics"):
        ui.stat_grid([
            ("Records", charts.fmt_int(m.get("total"))),
            ("Subdomains", charts.fmt_int(m.get("num_subdomains"))),
            ("Worst src share", charts.fmt_pct(conc.get("worst_share"))),
            ("Dup rate", charts.fmt_pct(m.get("dup_rate"))),
            ("Avg tokens", charts.fmt_int(q.get("avg_tokens"))),
            ("Drift", charts.fmt_pct(drift.get("max_delta"))),
            ("Topic CV", f"{m.get('topic_cv', 0.0):.2f}"),
        ], cols=4)

        # Per-subdomain volume + share, the gate's core evidence.
        subs = m.get("subdomains", {}) or {}
        dist = m.get("subdomain_distribution", {}) or {}
        if subs:
            st.markdown("**Records per sub-domain**")
            rows = [{"sub-domain": k, "records": v,
                     "share": charts.fmt_pct(dist.get(k))}
                    for k, v in sorted(subs.items(), key=lambda kv: kv[1],
                                       reverse=True)]
            ui.table(rows, height=300)

        feedback = eda.get("feedback", {}) or {}
        if feedback.get("recommendations"):
            st.markdown("**Actionable feedback (topic balance)**")
            for rec in feedback["recommendations"]:
                st.info(rec)

# ------------------------------------------------------------- fix balance -----
with ui.section("Fix balance",
                "Acts on the gate above: sources only the starved sub-domains, "
                "ingests and cleans what arrives, then looks again, until the "
                "corpus balances or discovery runs dry."):
    _running = control.status()["running"]
    _short = rebalance.lacking(eda) if eda else []

    if not eda:
        st.caption("Run the EDA stage first: the fix acts on its report.")
    elif rebalance.is_balanced(eda):
        st.success("The corpus is balanced. Nothing to fix.")
    elif not _short:
        # Not balanced, yet no sub-domain is starved: the spread itself is the
        # problem, and sourcing cannot aim at it. Capping would move the number by
        # deleting cleaned records, which this button does not do.
        st.info("No sub-domain is starved, but the corpus is still skewed. "
                "Sourcing cannot target this; see `clean balance --cap N` to trim "
                "the over-represented instead. That deletes cleaned records.")
    else:
        st.warning(f"{len(_short)} sub-domain(s) short of data: "
                   + ", ".join(_short))

    c = st.columns([1, 1, 2])
    _rounds = c[0].number_input(
        "Rounds", min_value=1, max_value=10, value=rebalance.DEFAULT_ROUNDS,
        key="fix_rounds",
        help="How many source-ingest-clean rounds to attempt before giving up. "
             "The run stops earlier once the corpus balances, or as soon as a "
             "round discovers no new sources.")
    _step = c[1].number_input(
        "Row step", min_value=5, max_value=500, value=rebalance.DEFAULT_ROW_STEP,
        key="fix_step",
        help="Extra catalog rows a round asks for when a starved sub-domain is "
             "already level with the best-covered one.")

    if st.button("Fix balance", key="fix_run", disabled=_running or not _short,
                 help="Runs in the background; watch it from the Overview page. "
                      "Only adds data: ingest and clean resume, so nothing "
                      "already fetched or cleaned is redone or deleted."):
        _res = control.start("eda-fix", settings={"fix_rounds": int(_rounds),
                                                  "fix_step": int(_step)})
        if _res.get("ok"):
            st.rerun()
        else:
            st.error(_res["error"])

    if _running:
        st.caption("A run is already active. Stop it from the Overview page "
                   "before starting a fix.")

# --------------------------------------------------------------- trends --------
with ui.section("Trends", "Metrics across past EDA runs."):
    rows = charts.eda_trend_rows(data.eda_history())
    if len(rows) < 2:
        st.caption("Need at least two EDA runs to chart trends.")
    else:
        st.line_chart({"total records": [r["total"] for r in rows]})
        st.line_chart({"dup rate": [r["dup_rate"] for r in rows],
                       "drift": [r["drift"] for r in rows]})
