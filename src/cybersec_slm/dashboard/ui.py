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
PILL = {"done": "done", "running": "running", "pending": "pending",
        "failed": "failed", "idle": "idle"}


def status_pill(state: str) -> str:
    """A plain-text label for a stage/run state (never raises; no emoji)."""
    return PILL.get(state, state)


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
    if c1.button(run_label, disabled=running, use_container_width=True,
                 key=f"{stage}_run"):
        res = control.start(stage, settings=settings)
        if res.get("ok"):
            st.rerun()
        else:
            st.error(res["error"])
    if c2.button("Stop", disabled=not running, use_container_width=True,
                 key=f"{stage}_stop"):
        control.stop()
        st.rerun()
    if running:
        st.caption(f"running: {cstat.get('stage') or 'pipeline'}  ·  "
                   f"pid {cstat['pid']}  ·  started {cstat.get('started_at')}")


def stage_header(key: str, states: dict) -> None:
    """Render a stage page header: just the stage label (no stage numbering)."""
    import streamlit as st

    stage = stages.get_stage(key)
    st.title(f"{stage.label}")


def stage_position(key: str) -> str:
    """'Stage N of 5' label for a stage key."""
    return f"Stage {stages.stage_keys().index(key) + 1} of {len(stages.STAGES)}"


def advanced_settings(stage: str, defaults: dict | None = None,
                      save_extra: dict | None = None) -> dict:
    """Render an expander of the advanced flags ``stage`` accepts; return settings.

    Only shows the widgets for flags that stage supports (mirrors the CLI via
    ``control._STAGE_FLAGS``), so every page reuses one consistent panel. Widgets
    are seeded from ``defaults`` when given, otherwise from the stage's saved
    settings (:mod:`settings_store`), so previously-saved values are the starting
    point and survive a restart. A "Save as defaults" button lives inside the
    panel; it persists the current settings merged with ``save_extra`` (used by the
    Sourcing page to also save its sub-domain / mode selection).
    """
    import streamlit as st

    from . import settings_store
    from .control import _STAGE_FLAGS

    allowed = _STAGE_FLAGS.get(stage, set())
    s: dict = {}
    if not allowed:
        return s
    base = dict(defaults) if defaults is not None else settings_store.get_stage(stage)

    def _clamp(v, lo, hi):
        return max(lo, min(hi, v))

    with st.expander("Advanced settings"):
        # Selective run by Sub-Domain (ingest/clean). The source stage renders its
        # own domain picker on the Sourcing page, so it is excluded here.
        if "domains" in allowed and stage != "source":
            from . import data
            opts = (data.raw_subdomains() if stage == "clean"
                    else data.catalog_subdomains())
            default_doms = [d for d in base.get("domains", []) if d in opts]
            picked = st.multiselect(
                "sub-domains to run (empty = all)", opts, default=default_doms,
                key=f"{stage}_domains",
                help="Selective run: only these Sub-Domains are processed; "
                     "everything else is left untouched.")
            if picked:
                s["domains"] = picked
        if "workers" in allowed:
            s["workers"] = int(st.number_input(
                "workers", 1, 32, value=_clamp(int(base.get("workers", 4)), 1, 32),
                key=f"{stage}_workers"))
        if "source_timeout" in allowed:
            s["source_timeout"] = int(st.number_input(
                "source timeout (s)", 30, 7200,
                value=_clamp(int(base.get("source_timeout", 1800)), 30, 7200),
                key=f"{stage}_timeout"))
        if "limit" in allowed:
            lim = int(st.number_input(
                "per-file record limit (0 = no cap)", 0, 10_000_000,
                value=_clamp(int(base.get("limit", 0)), 0, 10_000_000),
                key=f"{stage}_limit"))
            if lim:
                s["limit"] = lim
        if "max_source_gb" in allowed:
            gb = float(st.number_input(
                "max source size in GB (0 = no cap)", 0.0, 1000.0,
                value=_clamp(float(base.get("max_source_gb", 0.0)), 0.0, 1000.0),
                step=1.0, key=f"{stage}_maxgb"))
            if gb > 0:
                s["max_source_gb"] = gb
        if "sources" in allowed:
            src = st.text_input("sources CSV path (blank = default catalog)",
                                value=str(base.get("sources", "")),
                                key=f"{stage}_sources")
            if src.strip():
                s["sources"] = src.strip()
        if "per_keyword" in allowed:
            s["per_keyword"] = int(st.number_input(
                "results per keyword", 1, 50,
                value=_clamp(int(base.get("per_keyword", 5)), 1, 50),
                key=f"{stage}_perkw"))
        if "max_per_domain" in allowed:
            m = int(st.number_input(
                "max new sources per sub-domain (0 = no cap)", 0, 100_000,
                value=_clamp(int(base.get("max_per_domain", 0)), 0, 100_000),
                key=f"{stage}_maxdom"))
            if m:
                s["max_per_domain"] = m
        if "max_total" in allowed:
            t = int(st.number_input(
                "stop after N new sources total (0 = no cap)", 0, 1_000_000,
                value=_clamp(int(base.get("max_total", 0)), 0, 1_000_000),
                key=f"{stage}_maxtot"))
            if t:
                s["max_total"] = t
        if "searxng_url" in allowed:
            url = st.text_input(
                "SearXNG URL (blank = env SEARXNG_URL / localhost:8080)",
                value=str(base.get("searxng_url", "")), key=f"{stage}_searxurl")
            if url.strip():
                s["searxng_url"] = url.strip()
        if "language" in allowed:
            lang = st.text_input("search language", value=str(base.get("language", "en")),
                                 key=f"{stage}_lang")
            if lang.strip() and lang.strip() != "en":
                s["language"] = lang.strip()
        if "dry_run" in allowed:
            s["dry_run"] = st.checkbox(
                "dry run (write candidate CSV, do not append to the catalog)",
                value=bool(base.get("dry_run", False)), key=f"{stage}_dry")
        if "no_crawler" in allowed:
            enable = st.checkbox("crawl website sources this run",
                                 value=not bool(base.get("no_crawler", False)),
                                 key=f"{stage}_crawler")
            s["no_crawler"] = not enable
        if "drop_non_english" in allowed:
            s["drop_non_english"] = st.checkbox(
                "drop non-English records instead of translating them",
                value=bool(base.get("drop_non_english", False)),
                key=f"{stage}_dropnonen")
        if "purge_raw" in allowed:
            s["purge_raw"] = st.checkbox(
                "delete data/raw/ after cleaning",
                value=bool(base.get("purge_raw", False)), key=f"{stage}_purgeraw")
        if "no_auto_rebalance" in allowed:
            # Auto-rebalance is off by default; the flag is passed unless enabled.
            enable = st.checkbox("enable auto-rebalance",
                                 value=not bool(base.get("no_auto_rebalance", True)),
                                 key=f"{stage}_rebal")
            s["no_auto_rebalance"] = not enable
        if "no_enforce" in allowed:
            s["no_enforce"] = st.checkbox(
                "report only (do not fail on blockers)",
                value=bool(base.get("no_enforce", False)), key=f"{stage}_noenforce")
        if "fresh" in allowed:
            s["fresh"] = st.checkbox("fresh (ignore existing dataset)",
                                     value=bool(base.get("fresh", False)),
                                     key=f"{stage}_fresh")
        save_settings_button(stage, {**s, **(save_extra or {})},
                             key=f"{stage}_save")
    return s


def save_settings_button(stage: str, settings: dict, *, key: str,
                         label: str = "Save as defaults") -> None:
    """Render a button that persists ``settings`` as the saved defaults for ``stage``.

    Saved settings seed this stage's panel on the next load and feed the full
    pipeline run launched from the Overview page (:mod:`settings_store`).
    """
    import streamlit as st

    from . import settings_store

    if st.button(label, key=key,
                 help="Persist these settings; reused for this stage's own runs "
                      "and for the full pipeline run on the Overview page."):
        settings_store.save_stage(stage, settings)
        st.toast(f"Saved {stage} settings")
