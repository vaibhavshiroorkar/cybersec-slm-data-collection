#!/usr/bin/env python3
"""Streamlit entrypoint - the console landing / overview.

Presentation only; every value comes from :mod:`cybersec_slm.dashboard.data`.
Run with ``cybersec-slm dashboard`` or ``streamlit run
src/cybersec_slm/dashboard/app.py`` (after ``uv sync --extra dashboard``).
Streamlit auto-lists the ``pages/`` scripts in the sidebar.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import charts, data, theme, viz

st.set_page_config(page_title="cybersec-slm console", page_icon="🛡️",
                   layout="wide")
theme.inject()


@st.fragment(run_every=3)
def _overview() -> None:
    status = data.run_status()
    prog = data.live_progress(tail=0)
    man = data.manifest()
    eda = data.latest_eda()
    cat = data.catalog_summary()
    funnel = data.data_funnel()
    running = status["state"] == "running"

    # ---- hero: live pipeline state + corpus headline --------------------
    right = (theme.pill("running" if running else "idle",
                        "signal" if running else "muted", live=running)
             + f'<div class="mono" style="margin-top:8px">last activity '
               f'<b>{charts.fmt_age(status.get("age"))}</b></div>')
    records = man.get("record_count") if man else None
    subtitle = (f'{charts.fmt_int(records)} records collected across '
                f'{len(cat["by_domain"])} domains'
                if records else
                f'{cat["total"]} sources catalogued across '
                f'{len(cat["by_domain"])} domains, awaiting first run')
    theme.hero("Corpus Console", "cybersec-slm-data-collection", subtitle, right)
    st.caption(f"data root  ·  {data.data_root()}")

    # ---- instrument tiles ----------------------------------------------
    total = prog.get("total")
    gate_ok = bool(eda.get("passed")) if eda else None
    tiles = [
        {"label": "corpus records", "value": charts.fmt_int(records) if records else "-",
         "status": "signal"},
        {"label": "sources done",
         "value": f'{prog["completed"]}' + (f'/{total}' if total else ""),
         "status": "signal" if running else "muted",
         "sub": "of catalog" if total else None},
        {"label": "domains", "value": len(cat["by_domain"]) or "-", "status": "accent"},
        {"label": "final size",
         "value": f'{funnel["appended"]["size_mb"]:.0f}' if funnel["appended"]["lines"] else "-",
         "unit": "MB", "status": "pass" if funnel["appended"]["lines"] else "muted"},
        {"label": "eda gate",
         "value": ("PASS" if gate_ok else "FAIL") if eda else "-",
         "status": theme.status_of("gate", gate_ok) if eda else "muted"},
    ]
    theme.kpi_grid(tiles)


_overview()

# ---- corpus / catalog distribution -------------------------------------
_man = data.manifest()
theme.section(
    "Corpus composition" if _man else "Catalog composition",
    eyebrow="distribution",
    desc=("records per sub-domain in the released corpus" if _man
          else "sources per sub-domain in the curated catalog (pre-run)"))
_by = (_man.get("subdomains") if _man and _man.get("subdomains")
       else data.catalog_summary()["by_domain"])
_chart = viz.domain_bar(_by, value_label="records" if _man else "sources")
if _chart is not None:
    st.altair_chart(_chart, use_container_width=True)
else:
    st.caption("No catalog or corpus to chart yet.")

# ---- where to go --------------------------------------------------------
theme.section("Navigate", eyebrow="pages", desc="the console is read-only - it "
              "reflects what the pipeline has written")
st.markdown(
    '<div class="navgrid">'
    '<div class="navcard"><div class="k">01 · monitor</div>'
    '<div class="h">Pipeline</div><div class="d">Watch a run live, review the EDA '
    'sufficiency gate, trends across runs, the data funnel, per-source table and '
    'the release manifest.</div></div>'
    '<div class="navcard"><div class="k">02 · explore</div>'
    '<div class="h">Dataset</div><div class="d">Search, filter and page through the '
    'final corpus, and see what was rejected or de-duplicated on the way in.</div></div>'
    '<div class="navcard"><div class="k">03 · ask</div>'
    '<div class="h">Agent</div><div class="d">A read-only chat agent that answers '
    'questions about the run and the corpus, with a trace of what it looked up.</div></div>'
    '</div>',
    unsafe_allow_html=True)
