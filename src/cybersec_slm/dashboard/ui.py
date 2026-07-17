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


def _html_escape(s: str) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def page_header(key: str, states: dict | None = None) -> None:
    """Standardized stage-page header: sequence eyebrow, stage label, status pill.

    ``states`` is :func:`data.stage_states` output (``{key: {"state", ...}}``); the
    pill reflects this stage's state and is omitted when idle/unknown.
    """
    import streamlit as st

    profile_switcher()
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

    profile_switcher()
    st.markdown(f"<div class='ui-head'><h1>{_html_escape(title)}</h1></div>",
                unsafe_allow_html=True)
    if subtitle:
        st.caption(subtitle)


def profile_switcher() -> str:
    """Sidebar control for the active profile; returns the active profile name.

    Switching is a real, persisted change (``profiles.use``) that re-points every
    stage — the taxonomy sourcing searches on, the catalog ingestion reads, the
    sub-domain enum the schema validates against, and that profile's saved
    settings. It is therefore refused while a run is in flight, which would
    otherwise finish writing its output against a different corpus than it started
    with. Rendered on every page via :func:`app_header` / :func:`page_header`.
    """
    import streamlit as st

    from ..sourcing import profiles
    from . import data

    active = profiles.active()
    with st.sidebar:
        st.markdown("<div class='ui-eyebrow'>Profile</div>", unsafe_allow_html=True)
        names = profiles.names()
        running = data.run_status()["state"] == "running"
        picked = st.selectbox(
            "Active profile", names, index=names.index(active),
            key="profile_pick", disabled=running,
            label_visibility="collapsed",
            help="Which corpus every stage works on. Switching re-points the "
                 "taxonomy, the source catalog, and the saved settings.")
        if running:
            st.caption("Locked while a run is in flight.")
        elif picked != active:
            profiles.use(picked)
            st.rerun()

        info = profiles.info(active)
        st.caption(f"{info['domain_name']} · {len(info['subdomains'])} sub-domains "
                   f"· {info['catalog_rows']} sources")
    return active


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


def _stage_widgets(stage: str, base: dict) -> dict:
    """Render every run-configuration widget ``stage`` accepts; return the settings.

    Emits a widget for each flag in ``control._STAGE_FLAGS[stage]`` (mirrors the
    CLI), seeded from ``base`` (the stage's saved settings), and returns the
    collected settings dict. This is the shared body behind
    :func:`stage_config_dialog`: it renders the controls but neither wraps them in
    an expander nor persists anything, so the dialog owns the framing and the Save
    action. For the source stage it also renders the sub-domain / mode / caps
    controls that used to live on the Sourcing page, so the modal configures
    everything a run of that stage accepts.
    """
    import streamlit as st

    from .control import _STAGE_FLAGS

    allowed = _STAGE_FLAGS.get(stage, set())
    s: dict = {}
    if not allowed:
        return s

    def _clamp(v, lo, hi):
        return max(lo, min(hi, v))

    with st.container():
        # Selective run by Sub-Domain. For ingest/clean this scopes the run to
        # those Sub-Domains; for source it scopes discovery to them.
        picked_domains: list = []
        if "domains" in allowed:
            from . import data
            if stage == "source":
                opts = data.catalog_subdomains()
                label = "sub-domains to search (empty = all)"
                help_txt = ("Discovery searches only these Sub-Domains; empty "
                            "searches every configured Sub-Domain.")
            else:
                opts = (data.raw_subdomains() if stage == "clean"
                        else data.catalog_subdomains())
                label = "sub-domains to run (empty = all)"
                help_txt = ("Selective run: only these Sub-Domains are processed; "
                            "everything else is left untouched.")
            default_doms = [d for d in base.get("domains", []) if d in opts]
            picked_domains = st.multiselect(
                label, opts, default=default_doms, key=f"{stage}_domains",
                help=help_txt)
            if picked_domains:
                s["domains"] = picked_domains
        if "mode" in allowed:
            from ..sourcing import catalog
            _cur_mode = str(base.get("mode", catalog.MODES[0]))
            _mode_idx = (catalog.MODES.index(_cur_mode)
                         if _cur_mode in catalog.MODES else 0)
            s["mode"] = st.selectbox(
                "mode", catalog.MODES, index=_mode_idx, key=f"{stage}_mode",
                help="datasets: corpora/repos · text: articles/docs · both")
        if "target_per_domain" in allowed:
            tpd = int(st.number_input(
                "fill each sub-domain up to N valid rows (0 = off)", 0, 1_000_000,
                value=_clamp(int(base.get("target_per_domain") or 0), 0, 1_000_000),
                key=f"{stage}_targetdom",
                help="Fill mode: top each Sub-Domain up to this many "
                     "commercial-valid rows, filling only the deficit."))
            if tpd:
                s["target_per_domain"] = tpd
        # Row-level run: pick specific sources within (or across) the sub-domains.
        if "sources_only" in allowed and stage in ("ingest", "clean"):
            _row_selection(stage, base, picked_domains, s)
        if "workers" in allowed:
            _wdef = 12 if stage == "source" else 4
            worker_help = (
                "enrichment thread pool (license/metadata fetch)"
                if stage == "source"
                else "number of parallel worker processes (CPU cores) used to clean sources"
                if stage == "clean"
                else "process pool size (default: min(cpu, 8))")
            worker_label = (
                "clean workers" if stage == "clean"
                else "workers")
            s["workers"] = int(st.number_input(
                worker_label, 1, 32,
                value=_clamp(int(base.get("workers", _wdef)), 1, 32),
                key=f"{stage}_workers",
                help=worker_help))
        # No "resume from checkpoint" checkbox. Resuming is a property of a launch,
        # not of a stage's saved configuration: the Overview's Start and Resume both
        # already pass it. Saving it here meant a stale `resume: true` silently won
        # over the button the user actually pressed (see control.build_command),
        # which is a foot-gun with no upside.
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
                "gather until N new sources total (0 = single pass)", 0, 1_000_000,
                value=_clamp(int(base.get("max_total", 0)), 0, 1_000_000),
                key=f"{stage}_maxtot"))
            if t:
                s["max_total"] = t
        if "max_minutes" in allowed:
            mm = float(st.number_input(
                "time budget in minutes (0 = none)", 0.0, 600.0,
                value=_clamp(float(base.get("max_minutes") or 0.0), 0.0, 600.0),
                step=1.0, key=f"{stage}_maxmin",
                help="Stop after this long; combines with the source cap above "
                     "(whichever is hit first)."))
            if mm > 0:
                s["max_minutes"] = mm
        if "time_range" in allowed:
            _tr = ["any", "day", "week", "month", "year"]
            _cur = str(base.get("time_range", "year") or "year")
            tr = st.selectbox(
                "freshness (prefer results within)", _tr,
                index=_tr.index(_cur) if _cur in _tr else _tr.index("year"),
                key=f"{stage}_timerange",
                help="Falls back to unfiltered when a query would return nothing.")
            if tr != "year":
                s["time_range"] = tr
        if "no_site_scope" in allowed:
            scope_on = st.checkbox(
                "scope datasets queries to licensable hosts",
                value=not bool(base.get("no_site_scope", False)),
                key=f"{stage}_sitescope",
                help="HuggingFace, GitHub, Kaggle, Zenodo, arXiv, data.gov, UCI. "
                     "Falls back to an unscoped query when a scoped one finds nothing.")
            s["no_site_scope"] = not scope_on
        if "no_quality_filter" in allowed:
            qf_on = st.checkbox(
                "drop low-quality results (social/listing/search pages)",
                value=not bool(base.get("no_quality_filter", False)),
                key=f"{stage}_qualfilter")
            s["no_quality_filter"] = not qf_on
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
        # No enrichment toggle. Enrichment fills License, Author, size and Last
        # Updated, and License is what the ingestion gate reads: a row discovered
        # without it is unusable until a backfill resolves it. It is on by default
        # and there is no sensible reason to discover sources without it.
        if "dry_run" in allowed:
            s["dry_run"] = st.checkbox(
                "dry run (write candidate CSV, do not append to the catalog)",
                value=bool(base.get("dry_run", False)), key=f"{stage}_dry")
        # No "crawl website sources this run" toggle. Crawling is how a website-kind
        # row is fetched at all, so turning it off does not change how the run works,
        # it silently skips those sources: the same thing as not cataloguing them,
        # but discovered only later when their raw folders are missing. The stage
        # already has the extractor choice for the part that is a real decision.
        if "no_hazard_scan" in allowed:
            enable = st.checkbox(
                "scan for security hazards (script/iframe injection, base64 "
                "blobs, malware TLDs)",
                value=not bool(base.get("no_hazard_scan", False)),
                key=f"{stage}_hazardscan",
                help="Part of the light-EDA gate right after fetch. Turn off for "
                     "a non-security corpus where this check is irrelevant.")
            s["no_hazard_scan"] = not enable
        if "drop_non_english" in allowed:
            s["drop_non_english"] = st.checkbox(
                "drop non-English records instead of translating them",
                value=bool(base.get("drop_non_english", False)),
                key=f"{stage}_dropnonen")
        if "purge_raw" in allowed:
            s["purge_raw"] = st.checkbox(
                "delete data/raw/ after cleaning",
                value=bool(base.get("purge_raw", False)), key=f"{stage}_purgeraw")
        if "min_text_chars" in allowed:
            s["min_text_chars"] = int(st.number_input(
                "minimum text length in chars (below -> dropped)", 0, 10_000,
                value=_clamp(int(base.get("min_text_chars", 50)), 0, 10_000),
                key=f"{stage}_mintxt"))
        if "max_text_chars" in allowed:
            s["max_text_chars"] = int(st.number_input(
                "maximum text length in chars (above -> flagged)", 1_000, 1_000_000,
                value=_clamp(int(base.get("max_text_chars", 100_000)), 1_000, 1_000_000),
                key=f"{stage}_maxtxt"))
        if "garbage_max" in allowed:
            s["garbage_max"] = float(st.number_input(
                "max non-text char ratio before flagging", 0.0, 1.0,
                value=_clamp(float(base.get("garbage_max", 0.30)), 0.0, 1.0),
                step=0.01, key=f"{stage}_garbagemax"))
        if "repeat_max" in allowed:
            s["repeat_max"] = float(st.number_input(
                "max repeated-line/token ratio before flagging", 0.0, 1.0,
                value=_clamp(float(base.get("repeat_max", 0.50)), 0.0, 1.0),
                step=0.01, key=f"{stage}_repeatmax"))
        if "near_dup_threshold" in allowed:
            s["near_dup_threshold"] = float(st.number_input(
                "near-duplicate similarity threshold", 0.0, 1.0,
                value=_clamp(float(base.get("near_dup_threshold", 0.85)), 0.0, 1.0),
                step=0.01, key=f"{stage}_neardup"))
        if "shingle_size" in allowed:
            s["shingle_size"] = int(st.number_input(
                "word-shingle length for near-dup MinHash", 1, 20,
                value=_clamp(int(base.get("shingle_size", 5)), 1, 20),
                key=f"{stage}_shingle"))
        if "minhash_perm" in allowed:
            s["minhash_perm"] = int(st.number_input(
                "MinHash permutation count", 16, 512,
                value=_clamp(int(base.get("minhash_perm", 128)), 16, 512),
                step=16, key=f"{stage}_minhash"))
        if "allowed_langs" in allowed:
            langs = st.text_input(
                "allowed languages (comma-separated ISO codes)",
                value=", ".join(base.get("allowed_langs", ["en"])),
                key=f"{stage}_langs")
            parsed = [t.strip() for t in langs.split(",") if t.strip()]
            if parsed:
                s["allowed_langs"] = parsed
        if "pii_engine" in allowed:
            engines = ["regex", "presidio"]
            current = str(base.get("pii_engine", "regex"))
            s["pii_engine"] = st.selectbox(
                "PII engine",
                engines,
                index=engines.index(current) if current in engines else 0,
                key=f"{stage}_piiengine",
                help="regex (default) redacts emails, public IPs, valid cards and "
                     "SSNs at about 0.2 ms per record. presidio adds a spaCy NER "
                     "pass for person names on top, at roughly 300x that cost, and "
                     "needs `uv sync --extra pii-ner`. Person names in this corpus "
                     "are mostly public author bylines, so regex is the right "
                     "default; pick presidio for a deliberate audit pass.")
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
        if "min_total_records" in allowed:
            s["min_total_records"] = int(st.number_input(
                "minimum total records (blocker below this)", 0, 10_000_000,
                value=_clamp(int(base.get("min_total_records", 50)), 0, 10_000_000),
                key=f"{stage}_mintotal"))
        if "min_records_per_subdomain" in allowed:
            s["min_records_per_subdomain"] = int(st.number_input(
                "minimum records per sub-domain (warning below this)", 0, 1_000_000,
                value=_clamp(int(base.get("min_records_per_subdomain", 5)), 0, 1_000_000),
                key=f"{stage}_minpersub"))
        if "max_source_share" in allowed:
            s["max_source_share"] = float(st.number_input(
                "max share of a sub-domain one source may hold", 0.0, 1.0,
                value=_clamp(float(base.get("max_source_share", 0.60)), 0.0, 1.0),
                step=0.01, key=f"{stage}_maxsrcshare"))
        if "max_drift" in allowed:
            s["max_drift"] = float(st.number_input(
                "max topic-mix drift vs previous run", 0.0, 1.0,
                value=_clamp(float(base.get("max_drift", 0.25)), 0.0, 1.0),
                step=0.01, key=f"{stage}_maxdrift"))
        if "max_dup_rate" in allowed:
            s["max_dup_rate"] = float(st.number_input(
                "max exact-duplicate rate (warning above this)", 0.0, 1.0,
                value=_clamp(float(base.get("max_dup_rate", 0.40)), 0.0, 1.0),
                step=0.01, key=f"{stage}_maxduprate"))
        if "min_avg_tokens" in allowed:
            s["min_avg_tokens"] = float(st.number_input(
                "minimum average tokens per record", 0.0, 1000.0,
                value=_clamp(float(base.get("min_avg_tokens", 5.0)), 0.0, 1000.0),
                step=1.0, key=f"{stage}_minavgtok"))
        if "max_topic_cv" in allowed:
            s["max_topic_cv"] = float(st.number_input(
                "max coefficient of variation across topic sizes", 0.0, 10.0,
                value=_clamp(float(base.get("max_topic_cv", 1.5)), 0.0, 10.0),
                step=0.1, key=f"{stage}_maxtopiccv"))
        if "min_subdomain_share" in allowed:
            s["min_subdomain_share"] = float(st.number_input(
                "minimum share of the corpus a sub-domain must hold", 0.0, 1.0,
                value=_clamp(float(base.get("min_subdomain_share", 0.01)), 0.0, 1.0),
                step=0.01, key=f"{stage}_minsubshare"))
        if "owner" in allowed:
            owner = st.text_input(
                "team name recorded on the EDA report",
                value=str(base.get("owner", "data-collection-team")),
                key=f"{stage}_owner")
            if owner.strip():
                s["owner"] = owner.strip()
        if "fresh" in allowed:
            s["fresh"] = st.checkbox("fresh (ignore existing dataset)",
                                     value=bool(base.get("fresh", False)),
                                     key=f"{stage}_fresh")
    return s


def stage_config_dialog(stage: str) -> None:
    """Open a modal that configures every setting for one pipeline ``stage``.

    Rendered from the Overview page's per-stage Advanced buttons. Seeds each widget
    from the stage's saved settings, and a single "Save as defaults" button
    persists the collected settings (:mod:`settings_store`) and closes the dialog.
    The saved settings seed this dialog next time and feed the full pipeline run
    launched from the Overview page. There is no Run action here: running is done
    from the Overview page.
    """
    import streamlit as st

    from . import settings_store

    try:
        label = stages.get_stage(stage).label
    except (KeyError, AttributeError):
        label = stage.capitalize()

    @st.dialog(f"Configure {label}")
    def _dialog() -> None:
        st.caption("These settings are saved for this stage and used by the full "
                   "pipeline run on this page.")
        base = settings_store.get_stage(stage)
        s = _stage_widgets(stage, base)
        if st.button("Save as defaults", key=f"{stage}_modal_save",
                     type="primary", use_container_width=True):
            settings_store.save_stage(stage, s)
            st.toast(f"Saved {label} settings")
            st.rerun()

    _dialog()


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
