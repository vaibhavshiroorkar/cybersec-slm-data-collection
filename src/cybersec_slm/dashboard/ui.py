#!/usr/bin/env python3
"""Shared presentation helpers for the dashboard pages.

Keeps every page visually identical and short, and centralizes the layout choices
that make the dashboard feel stable (no jumping): fixed-height, scrollable
containers for logs and long tables, consistent metric grids, and one small CSS
injection. Streamlit is imported lazily inside each rendering helper so this module
(and the pure ``status_pill``) imports without the optional ``dashboard`` extra.
"""

from __future__ import annotations

from contextlib import contextmanager

from .. import stages

# Status vocabulary shared by the Overview strip and the stage-page headers.
PILL = {"done": "done", "running": "running", "pending": "pending",
        "failed": "failed", "idle": "idle"}


def status_pill(state: str) -> str:
    """A plain-text label for a stage/run state (never raises; no emoji)."""
    return PILL.get(state, state)


def inject_css() -> None:
    """Inject the dashboard stylesheet once per session.

    A quiet "instrument panel" layer over Streamlit: hairline-bordered section
    cards, an uppercase eyebrow label, a status pill, and monospace tabular
    numerals in the stat tiles. Surfaces use theme-neutral ``rgba`` so the look
    holds in both light and dark; the accent comes from ``.streamlit/config.toml``.
    """
    import streamlit as st

    if st.session_state.get("_ui_css"):
        return
    st.session_state["_ui_css"] = True
    st.markdown(
        """
        <style>
          section.main div.block-container { padding-top: 2.6rem;
            max-width: 1200px; }

          /* Section cards: st.container(border=True) wrapper. */
          div[data-testid="stVerticalBlockBorderWrapper"] {
            border: 1px solid rgba(128,128,128,0.22) !important;
            border-radius: 0.6rem; padding: 0.4rem 0.15rem;
            background: rgba(128,128,128,0.035); }

          /* Uppercase eyebrow label used for card titles and the page header. */
          .ui-eyebrow { text-transform: uppercase; letter-spacing: 0.09em;
            font-size: 0.72rem; font-weight: 600; opacity: 0.62;
            margin: 0.1rem 0 0.35rem 0; }

          /* Page header: sequence eyebrow + title + status pill. */
          .ui-head { display: flex; align-items: baseline; gap: 0.75rem;
            flex-wrap: wrap; margin-bottom: 0.15rem; }
          .ui-head h1 { margin: 0; font-size: 1.9rem; letter-spacing: -0.01em; }
          .ui-pill { font-size: 0.72rem; font-weight: 600; padding: 0.1rem 0.55rem;
            border-radius: 999px; text-transform: uppercase; letter-spacing: 0.05em;
            border: 1px solid rgba(128,128,128,0.35); opacity: 0.9; }
          .ui-pill.s-done    { color: #2f9e44; border-color: rgba(47,158,68,0.5); }
          .ui-pill.s-running { color: #f08c00; border-color: rgba(240,140,0,0.5); }
          .ui-pill.s-failed  { color: #e03131; border-color: rgba(224,49,49,0.5); }

          /* Stat tiles: monospace tabular readouts, consistent footprint. */
          div[data-testid="stMetric"] { padding: 0.35rem 0.65rem;
            background: rgba(128,128,128,0.06); border-radius: 0.5rem; }
          div[data-testid="stMetricValue"] { font-size: 1.35rem;
            font-variant-numeric: tabular-nums;
            font-family: ui-monospace, "Cascadia Code", "Consolas", monospace; }
          div[data-testid="stMetricLabel"] { text-transform: uppercase;
            letter-spacing: 0.05em; font-size: 0.72rem; opacity: 0.72; }

          div[data-testid="stCode"] { max-height: 100%; }
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


def _html_escape(s: str) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def page_header(key: str, states: dict | None = None) -> None:
    """Standardized stage-page header: sequence eyebrow, stage label, status pill.

    ``states`` is :func:`data.stage_states` output (``{key: {"state", ...}}``); the
    pill reflects this stage's state and is omitted when idle/unknown.
    """
    import streamlit as st

    stage = stages.get_stage(key)
    state = ((states or {}).get(key) or {}).get("state", "idle")
    pill = ""
    if state in ("done", "running", "failed", "pending"):
        pill = (f"<span class='ui-pill s-{state}'>{status_pill(state)}</span>")
    st.markdown(
        f"<div class='ui-eyebrow'>{stage_position(key)}</div>"
        f"<div class='ui-head'><h1>{_html_escape(stage.label)}</h1>{pill}</div>",
        unsafe_allow_html=True)


def app_header(title: str, subtitle: str | None = None) -> None:
    """Header for the non-stage pages (Overview, Agent): title + optional subtitle."""
    import streamlit as st

    st.markdown(f"<div class='ui-head'><h1>{_html_escape(title)}</h1></div>",
                unsafe_allow_html=True)
    if subtitle:
        st.caption(subtitle)


@contextmanager
def section(title: str, subtitle: str | None = None):
    """A bordered section card with an uppercase eyebrow title.

    Replaces the old ``subheader`` + ``divider`` pattern::

        with ui.section("Run this stage"):
            ...

    Yields the container so callers can also target it directly if needed.
    """
    import streamlit as st

    box = st.container(border=True)
    with box:
        st.markdown(f"<div class='ui-eyebrow'>{_html_escape(title)}</div>",
                    unsafe_allow_html=True)
        if subtitle:
            st.caption(subtitle)
        yield box


def stage_position(key: str) -> str:
    """'Stage N of 5' label for a stage key."""
    return f"Stage {stages.stage_keys().index(key) + 1} of {len(stages.STAGES)}"


def _saved_row_range(saved: list[str], rows: list[dict], n: int) -> tuple[int, int]:
    """Default (from, to) row numbers for the range widget, seeded from saved ids.

    Only reseeds when the saved ``sources_only`` ids are exactly the contiguous
    block they span in ``rows``; otherwise returns the full ``(1, n)`` (= no
    selection), so a saved range round-trips but a scattered saved set does not
    silently expand into a filled-in range.
    """
    idset = {s for s in saved if s}
    if not idset:
        return 1, n
    positions = [i for i, r in enumerate(rows) if r["id"] and r["id"] in idset]
    if not positions:
        return 1, n
    lo, hi = min(positions), max(positions)
    block = {rows[i]["id"] for i in range(lo, hi + 1) if rows[i]["id"]}
    return (lo + 1, hi + 1) if block == idset else (1, n)


def _row_selection(stage: str, base: dict, picked_domains: list, s: dict) -> None:
    """Render the specific-source ("row") picker for ingest/clean; set
    ``s['sources_only']``.

    With sub-domain(s) chosen, a nested multiselect lists only their sources
    (empty = all of them). With none chosen, a start/end row-number range selects
    a contiguous block of the full stage list (empty / full range = all sources).
    Ingest rows are catalog rows (ids are Dataset Links) in ``Sources.csv`` order;
    clean rows are ``<sub-domain>/<source>`` raw folders in stable order.
    """
    import streamlit as st

    from . import data

    rows = (data.clean_source_rows() if stage == "clean"
            else data.ingest_source_rows())
    saved = [str(x) for x in base.get("sources_only", []) if str(x)]

    if picked_domains:
        wanted = set(picked_domains)
        subset = [r for r in rows if r["subdomain"] in wanted and r["id"]]
        if not subset:
            st.caption("No sources found for the selected sub-domain(s) yet.")
            return
        id_by_label: dict[str, str] = {}
        labels: list[str] = []
        for i, r in enumerate(subset):
            label = f"{r['label']}  ·  {r['subdomain']}"
            if label in id_by_label:
                label = f"{label}  #{i}"
            id_by_label[label] = r["id"]
            labels.append(label)
        saved_set = set(saved)
        default_labels = [la for la, rid in id_by_label.items() if rid in saved_set]
        chosen = st.multiselect(
            "specific sources to run (empty = all in the chosen sub-domains)",
            labels, default=default_labels, key=f"{stage}_rows",
            help="Row-level run: only these sources are processed. Leave empty to "
                 "run every source in the selected sub-domain(s).")
        ids = [id_by_label[la] for la in chosen]
        if ids:
            s["sources_only"] = ids
        return

    # No sub-domain selected: pick a contiguous row-number range over the full list.
    n = len(rows)
    if not n:
        st.caption("No sources available to range over yet.")
        return
    lo_default, hi_default = _saved_row_range(saved, rows, n)
    c1, c2 = st.columns(2)
    start = int(c1.number_input("from row #", 1, n, value=lo_default,
                                key=f"{stage}_row_from"))
    end = int(c2.number_input("to row #", 1, n, value=hi_default,
                              key=f"{stage}_row_to"))
    lo, hi = min(start, end), max(start, end)
    if not (lo == 1 and hi == n):
        ids = [rows[i]["id"] for i in range(lo - 1, hi) if rows[i]["id"]]
        if ids:
            s["sources_only"] = ids
    order = "Sources.csv" if stage == "ingest" else "clean"
    with st.expander(f"Numbered source list ({n}, in {order} order)"):
        st.caption("The range above selects this block by the '#' column. A full "
                   "range (1 to the last row) or an empty range means all sources.")
        table([{"source": r["label"], "sub-domain": r["subdomain"]} for r in rows],
              height=300)


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
        picked_domains: list = []
        if "domains" in allowed and stage != "source":
            from . import data
            opts = (data.raw_subdomains() if stage == "clean"
                    else data.catalog_subdomains())
            default_doms = [d for d in base.get("domains", []) if d in opts]
            picked_domains = st.multiselect(
                "sub-domains to run (empty = all)", opts, default=default_doms,
                key=f"{stage}_domains",
                help="Selective run: only these Sub-Domains are processed; "
                     "everything else is left untouched.")
            if picked_domains:
                s["domains"] = picked_domains
        # Row-level run: pick specific sources within (or across) the sub-domains.
        if "sources_only" in allowed and stage in ("ingest", "clean"):
            _row_selection(stage, base, picked_domains, s)
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
        if "no_enrich" in allowed:
            enrich_on = st.checkbox(
                "enrich discovered sources with metadata "
                "(size, license, last updated, author, popularity, tags)",
                value=not bool(base.get("no_enrich", False)), key=f"{stage}_enrich",
                help="Fetches per-source metadata from the host (HuggingFace, "
                     "GitHub, or an HTTP HEAD). Adds a network call per source; "
                     "set $GITHUB_TOKEN to raise GitHub's rate limit.")
            s["no_enrich"] = not enrich_on
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


def right_slot():
    """A column pinned bottom-right, for a section's trailing Save/action button.

    Usage::

        if ui.right_slot().button("Save", use_container_width=True):
            ...
    """
    import streamlit as st

    return st.columns([3, 1])[1]


def save_settings_button(stage: str, settings: dict, *, key: str,
                         label: str = "Save as defaults") -> None:
    """Render a bottom-right button that persists ``settings`` for ``stage``.

    Saved settings seed this stage's panel on the next load and feed the full
    pipeline run launched from the Overview page (:mod:`settings_store`).
    """
    import streamlit as st

    from . import settings_store

    if right_slot().button(label, key=key, use_container_width=True,
                           help="Persist these settings; reused for this stage's "
                                "own runs and for the full pipeline run."):
        settings_store.save_stage(stage, settings)
        st.toast(f"Saved {stage} settings")
