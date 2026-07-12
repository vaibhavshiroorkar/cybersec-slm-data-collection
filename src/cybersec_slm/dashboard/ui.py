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
    """Inject the dashboard stylesheet once per session (stable, premium spacing)."""
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


def stat_grid(pairs, cols: int = 4) -> None:
    """Lay ``(label, value)`` pairs into a stable ``cols``-wide metric grid."""
    import streamlit as st

    pairs = list(pairs)
    columns = st.columns(cols)
    for i, (label, value) in enumerate(pairs):
        columns[i % cols].metric(label, value)


def stage_header(key: str, states: dict) -> None:
    """Render a stage page header: the stage label + its status pill."""
    import streamlit as st

    stage = stages.get_stage(key)
    state = (states.get(key) or {}).get("state", "idle")
    st.title(f"{stage.label}")
    st.caption(f"Stage {stages.stage_keys().index(key) + 1} of 5  ·  "
               f"{status_pill(state)}")


def stage_position(key: str) -> str:
    """'Stage N of 5' label for a stage key."""
    return f"Stage {stages.stage_keys().index(key) + 1} of {len(stages.STAGES)}"
