#!/usr/bin/env python3
"""Shared presentation helpers for the dashboard pages.

Keeps every page visually identical and short, and centralizes the layout choices
that make the dashboard feel stable (no jumping): fixed-height, scrollable
containers for logs and long tables, consistent metric grids, and one small CSS
injection. Streamlit is imported lazily inside each rendering helper so this module
(and the pure ``status_pill``) imports without the optional ``dashboard`` extra.
"""

from __future__ import annotations

from .. import stages

# Status vocabulary shared by the Overview strip and the stage-page headers.
PILL = {"done": "✅", "running": "🟢", "pending": "○", "failed": "⛔", "idle": "○"}


def status_pill(state: str) -> str:
    """A compact ``<emoji> <state>`` label for a stage/run state (never raises)."""
    return f"{PILL.get(state, '○')} {state}"


def inject_css() -> None:
    """Inject the dashboard stylesheet once per session (stable, quiet spacing)."""
    import streamlit as st

    if st.session_state.get("_ui_css"):
        return
    st.session_state["_ui_css"] = True
    st.markdown(
        """
        <style>
          /* tighter, consistent metric tiles so rows never reflow on refresh */
          div[data-testid="stMetric"] { padding: 0.35rem 0.6rem;
            background: rgba(128,128,128,0.06); border-radius: 0.5rem; }
          div[data-testid="stMetricValue"] { font-size: 1.35rem; }
          /* scrollable code/log boxes keep a fixed footprint */
          div[data-testid="stCode"] { max-height: 100%; }
          section.main div.block-container { padding-top: 2.2rem; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def log_box(lines, height: int = 320) -> None:
    """Render log lines in a fixed-height, scrollable box (they scroll, not reflow)."""
    import streamlit as st

    text = "\n".join(lines) if lines else "(no pipeline log yet)"
    with st.container(height=height):
        st.code(text, language="log")


def table(rows, height: int | None = None) -> None:
    """Render rows as a dataframe with an Excel-style 1-based ``#`` row number.

    Streamlit hides the frame index by default; here it is shown and renumbered
    from 1 so every table reads like a spreadsheet. ``height`` is passed to the
    dataframe itself (not a wrapping container) so Streamlit's search / download /
    fullscreen toolbar stays visible instead of being clipped. Empty input renders
    a small caption.
    """
    import pandas as pd
    import streamlit as st

    rows = list(rows)
    if not rows:
        st.caption("(nothing to show)")
        return
    df = pd.DataFrame(rows)
    df.index = range(1, len(df) + 1)
    df.index.name = "#"
    kwargs = {"height": height} if height else {}
    st.dataframe(df, use_container_width=True, hide_index=False, **kwargs)


def stat_grid(pairs, cols: int = 4) -> None:
    """Lay ``(label, value)`` pairs into a stable ``cols``-wide metric grid."""
    import streamlit as st

    pairs = list(pairs)
    columns = st.columns(cols)
    for i, (label, value) in enumerate(pairs):
        columns[i % cols].metric(label, value)


def stage_run_control(stage: str, *, run_label: str = "Run this stage") -> None:
    """Render the run control for one stage: advanced settings + Run / Stop.

    Launches ``control.start(stage, settings=...)`` and stops the active run. Only
    one stage runs at a time, so Run is disabled while any stage is live.
    """
    import streamlit as st

    from . import control

    cstat = control.status()
    running = cstat["running"]
    settings = advanced_settings(stage)
    c1, c2 = st.columns(2)
    if c1.button(f"▶ {run_label}", disabled=running, use_container_width=True,
                 key=f"{stage}_run"):
        res = control.start(stage, settings=settings)
        if res.get("ok"):
            st.rerun()
        else:
            st.error(res["error"])
    if c2.button("⏹ Stop", disabled=not running, use_container_width=True,
                 key=f"{stage}_stop"):
        control.stop()
        st.rerun()
    if running:
        st.caption(f"● running: {cstat.get('stage') or 'pipeline'}  ·  "
                   f"pid {cstat['pid']}  ·  started {cstat.get('started_at')}")


def stage_header(key: str, states: dict) -> None:
    """Render a stage page header: just the stage label (no stage numbering)."""
    import streamlit as st

    stage = stages.get_stage(key)
    st.title(f"{stage.label}")


def stage_position(key: str) -> str:
    """'Stage N of 5' label for a stage key."""
    return f"Stage {stages.stage_keys().index(key) + 1} of {len(stages.STAGES)}"


def advanced_settings(stage: str) -> dict:
    """Render an expander of the advanced flags ``stage`` accepts; return settings.

    Only shows the widgets for flags that stage supports (mirrors the CLI via
    ``control._STAGE_FLAGS``), so every page reuses one consistent panel.
    """
    import streamlit as st

    from .control import _STAGE_FLAGS

    allowed = _STAGE_FLAGS.get(stage, set())
    s: dict = {}
    if not allowed:
        return s
    with st.expander("Advanced settings"):
        # Selective run by Sub-Domain (ingest/clean). The source stage renders its
        # own domain picker on the Sourcing page, so it is excluded here.
        if "domains" in allowed and stage != "source":
            from . import data
            opts = (data.raw_subdomains() if stage == "clean"
                    else data.catalog_subdomains())
            picked = st.multiselect(
                "sub-domains to run (empty = all)", opts, key=f"{stage}_domains",
                help="Selective run: only these Sub-Domains are processed; "
                     "everything else is left untouched.")
            if picked:
                s["domains"] = picked
        if "workers" in allowed:
            s["workers"] = int(st.number_input(
                "workers", 1, 32, value=4, key=f"{stage}_workers"))
        if "source_timeout" in allowed:
            s["source_timeout"] = int(st.number_input(
                "source timeout (s)", 30, 7200, value=1800, key=f"{stage}_timeout"))
        if "limit" in allowed:
            lim = int(st.number_input("per-file record limit (0 = no cap)", 0,
                                      10_000_000, value=0, key=f"{stage}_limit"))
            if lim:
                s["limit"] = lim
        if "max_source_gb" in allowed:
            gb = float(st.number_input("max source size in GB (0 = no cap)", 0.0,
                                       1000.0, value=0.0, step=1.0,
                                       key=f"{stage}_maxgb"))
            if gb > 0:
                s["max_source_gb"] = gb
        if "sources" in allowed:
            src = st.text_input("sources CSV path (blank = default catalog)",
                                key=f"{stage}_sources")
            if src.strip():
                s["sources"] = src.strip()
        if "per_keyword" in allowed:
            s["per_keyword"] = int(st.number_input(
                "results per keyword", 1, 50, value=5, key=f"{stage}_perkw"))
        if "max_per_domain" in allowed:
            m = int(st.number_input("max new sources per sub-domain (0 = no cap)",
                                    0, 100_000, value=0, key=f"{stage}_maxdom"))
            if m:
                s["max_per_domain"] = m
        if "max_total" in allowed:
            t = int(st.number_input("stop after N new sources total (0 = no cap)",
                                    0, 1_000_000, value=0, key=f"{stage}_maxtot"))
            if t:
                s["max_total"] = t
        if "dry_run" in allowed:
            s["dry_run"] = st.checkbox(
                "dry run (write candidate CSV, do not append to the catalog)",
                key=f"{stage}_dry")
        if "no_crawler" in allowed:
            enable = st.checkbox("crawl website sources this run", value=True,
                                 key=f"{stage}_crawler")
            s["no_crawler"] = not enable
        if "drop_non_english" in allowed:
            s["drop_non_english"] = st.checkbox(
                "drop non-English records instead of translating them",
                key=f"{stage}_dropnonen")
        if "purge_raw" in allowed:
            s["purge_raw"] = st.checkbox(
                "delete data/raw/ after cleaning", key=f"{stage}_purgeraw")
        if "no_auto_rebalance" in allowed:
            # Auto-rebalance is off by default; the flag is passed unless enabled.
            enable = st.checkbox("enable auto-rebalance", value=False,
                                 key=f"{stage}_rebal")
            s["no_auto_rebalance"] = not enable
        if "no_enforce" in allowed:
            s["no_enforce"] = st.checkbox(
                "report only (do not fail on blockers)", key=f"{stage}_noenforce")
        if "fresh" in allowed:
            s["fresh"] = st.checkbox("fresh (ignore existing dataset)",
                                     key=f"{stage}_fresh")
    return s
