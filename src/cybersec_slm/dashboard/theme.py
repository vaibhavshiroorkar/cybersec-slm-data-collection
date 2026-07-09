#!/usr/bin/env python3
"""Presentation theme for the dashboard - a security-operations console.

Streamlit-facing (imports streamlit), so it lives outside the tested read layer
(``data.py``) and formatting helpers (``charts.py``). Provides:

* :func:`inject` - one CSS injection (fonts, palette, instrument-tile styling).
* :func:`hero` - the console status header at the top of a page.
* :func:`kpi_grid` - a responsive row of instrument tiles (the signature element).
* :func:`section` - an eyebrow + title section marker.
* :func:`pill` / :func:`status_of` - status pills and their semantic colors.

Every figure is set in a monospace face on purpose: counts, hashes and rates are
instrument readouts, not prose.
"""

from __future__ import annotations

import html

import streamlit as st

# Semantic status -> accent colour. Multiple functional accents (not one
# decorative highlight) because the domain is all about state: active, healthy,
# degraded, failed.
STATUS_COLORS = {
    "signal": "#38BDF8",   # active / primary
    "pass": "#34D399",     # healthy
    "warn": "#FBBF24",     # degraded
    "fail": "#F87171",     # failed
    "muted": "#64748B",    # inactive / n/a
    "accent": "#A78BFA",   # secondary series
}

_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@500;600&display=swap');

:root {
  --bg:#0E1522; --panel:#16202F; --panel-2:#1C2838; --line:#263447;
  --ink:#E6EDF5; --muted:#8A9BB0;
  --signal:#38BDF8; --pass:#34D399; --warn:#FBBF24; --fail:#F87171; --accent:#A78BFA;
  --mono:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,monospace;
  --display:'Space Grotesk',system-ui,sans-serif;
  --body:'Inter',system-ui,-apple-system,sans-serif;
}

/* base */
html, body, [class*="css"] { font-family: var(--body); }
.stApp {
  background:
    radial-gradient(1100px 500px at 82% -6%, rgba(56,189,248,.08), transparent 60%),
    radial-gradient(900px 500px at 4% 0%, rgba(167,139,250,.06), transparent 55%),
    var(--bg);
}
.block-container { padding-top: 2.4rem; max-width: 1240px; }
h1, h2, h3 { font-family: var(--display); letter-spacing:-.01em; color:var(--ink); }
h1 { font-weight:700; } h2,h3 { font-weight:600; }
a { color: var(--signal); }

/* sidebar */
[data-testid="stSidebar"] { background:#0B111C; border-right:1px solid var(--line); }
[data-testid="stSidebar"] .block-container { padding-top:1.5rem; }

/* ---- hero: the console status header ---------------------------------- */
.soc-hero {
  border:1px solid var(--line); border-radius:14px; padding:22px 24px; margin-bottom:6px;
  background:
     linear-gradient(180deg, rgba(56,189,248,.05), rgba(22,32,47,0)) ,
     var(--panel);
  position:relative; overflow:hidden;
}
.soc-hero::after{ content:""; position:absolute; inset:0;
  background-image:linear-gradient(var(--line) 1px, transparent 1px);
  background-size:100% 26px; opacity:.10; pointer-events:none; }
.soc-hero .eyebrow{ font-family:var(--mono); font-size:11px; letter-spacing:.28em;
  text-transform:uppercase; color:var(--signal); }
.soc-hero h1{ margin:.15rem 0 .1rem; font-size:2.15rem; }
.soc-hero .sub{ color:var(--muted); font-size:.95rem; }
.soc-hero .mono{ font-family:var(--mono); color:var(--muted); }
.soc-hero .mono b{ color:var(--ink); font-weight:600; }

/* ---- status pill ------------------------------------------------------ */
.pill{ display:inline-flex; align-items:center; gap:7px; font-family:var(--mono);
  font-size:12px; font-weight:600; padding:4px 11px; border-radius:999px;
  border:1px solid var(--line); background:var(--panel-2); color:var(--ink); }
.pill .dot{ width:8px; height:8px; border-radius:50%; box-shadow:0 0 0 0 currentColor; }
.pill.live .dot{ animation:pulse 1.8s infinite; }
@keyframes pulse{ 0%{box-shadow:0 0 0 0 rgba(56,189,248,.5);}
  70%{box-shadow:0 0 0 7px rgba(56,189,248,0);} 100%{box-shadow:0 0 0 0 rgba(56,189,248,0);} }
@media (prefers-reduced-motion: reduce){ .pill.live .dot{ animation:none; } }

/* ---- instrument tiles (the signature) --------------------------------- */
.kpi-grid{ display:grid; gap:14px; grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
  margin:.4rem 0 .2rem; }
.kpi{ position:relative; border:1px solid var(--line); border-radius:12px;
  background:var(--panel); padding:16px 16px 14px; overflow:hidden; }
.kpi::before{ content:""; position:absolute; top:0; left:0; right:0; height:3px;
  background:var(--_c,var(--signal)); opacity:.9; }
.kpi .label{ font-family:var(--mono); font-size:10.5px; letter-spacing:.16em;
  text-transform:uppercase; color:var(--muted); }
.kpi .value{ font-family:var(--mono); font-size:1.9rem; font-weight:600;
  line-height:1.1; margin-top:6px; color:var(--ink); }
.kpi .value .unit{ font-size:.9rem; color:var(--muted); margin-left:3px; }
.kpi .sub{ font-size:12px; color:var(--muted); margin-top:4px; }
.kpi .sub .up{ color:var(--pass); } .kpi .sub .down{ color:var(--fail); }

/* ---- section marker --------------------------------------------------- */
.section-head{ margin:1.6rem 0 .5rem; }
.section-head .eyebrow{ font-family:var(--mono); font-size:10.5px; letter-spacing:.22em;
  text-transform:uppercase; color:var(--signal); }
.section-head .title{ font-family:var(--display); font-size:1.18rem; font-weight:600;
  color:var(--ink); }
.section-head .desc{ color:var(--muted); font-size:.9rem; }
.section-head .rule{ height:1px; background:linear-gradient(90deg,var(--line),transparent);
  margin-top:.5rem; }

/* ---- nav cards -------------------------------------------------------- */
.navgrid{ display:grid; gap:14px; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); }
.navcard{ border:1px solid var(--line); border-radius:12px; background:var(--panel);
  padding:16px 18px; }
.navcard .k{ font-family:var(--mono); font-size:11px; letter-spacing:.14em;
  text-transform:uppercase; color:var(--signal); }
.navcard .h{ font-family:var(--display); font-weight:600; font-size:1.05rem; margin:.2rem 0; }
.navcard .d{ color:var(--muted); font-size:.88rem; }

/* ---- widgets ---------------------------------------------------------- */
.stButton button{ border:1px solid var(--line); background:var(--panel-2); color:var(--ink);
  border-radius:9px; font-weight:600; }
.stButton button:hover{ border-color:var(--signal); color:var(--signal); }
code, pre, .stCode { font-family:var(--mono) !important; }
[data-testid="stMetricValue"]{ font-family:var(--mono); }
hr{ border-color:var(--line); }
</style>
"""


def inject() -> None:
    """Inject the console CSS once per session run (idempotent within a rerun)."""
    st.markdown(_CSS, unsafe_allow_html=True)


def status_of(kind: str, ok: bool | None = None) -> str:
    """Map a semantic hint to a status key used for accent colours."""
    if kind == "run":
        return "signal" if ok else "muted"
    if kind == "gate":
        return "pass" if ok else "fail"
    return kind if kind in STATUS_COLORS else "signal"


def pill(text: str, status: str = "signal", live: bool = False) -> str:
    """Return HTML for a status pill (caller renders via ``st.markdown``)."""
    c = STATUS_COLORS.get(status, STATUS_COLORS["signal"])
    cls = "pill live" if live else "pill"
    return (f'<span class="{cls}"><span class="dot" style="background:{c};color:{c}">'
            f'</span>{html.escape(text)}</span>')


def hero(title: str, eyebrow: str, subtitle: str = "", right_html: str = "") -> None:
    """Render the console status header."""
    st.markdown(
        f'<div class="soc-hero">'
        f'<div style="display:flex;justify-content:space-between;align-items:flex-start;'
        f'gap:16px;flex-wrap:wrap;position:relative;z-index:1">'
        f'<div><div class="eyebrow">{html.escape(eyebrow)}</div>'
        f'<h1>{html.escape(title)}</h1>'
        f'<div class="sub">{subtitle}</div></div>'
        f'<div style="text-align:right">{right_html}</div>'
        f'</div></div>',
        unsafe_allow_html=True)


def kpi_grid(items: list[dict]) -> None:
    """Render a responsive row of instrument tiles.

    Each item: ``{"label", "value", "sub"?, "unit"?, "status"?}``. ``value`` is
    pre-formatted; ``status`` picks the top-rule colour (default ``signal``).
    """
    cells = []
    for it in items:
        c = STATUS_COLORS.get(it.get("status", "signal"), STATUS_COLORS["signal"])
        unit = f'<span class="unit">{html.escape(str(it["unit"]))}</span>' if it.get("unit") else ""
        sub = f'<div class="sub">{it["sub"]}</div>' if it.get("sub") else ""
        cells.append(
            f'<div class="kpi" style="--_c:{c}">'
            f'<div class="label">{html.escape(str(it["label"]))}</div>'
            f'<div class="value">{html.escape(str(it["value"]))}{unit}</div>'
            f'{sub}</div>')
    st.markdown(f'<div class="kpi-grid">{"".join(cells)}</div>', unsafe_allow_html=True)


def section(title: str, eyebrow: str = "", desc: str = "") -> None:
    """Render an eyebrow + title section marker with a hairline rule."""
    eb = f'<div class="eyebrow">{html.escape(eyebrow)}</div>' if eyebrow else ""
    ds = f'<div class="desc">{html.escape(desc)}</div>' if desc else ""
    st.markdown(
        f'<div class="section-head">{eb}'
        f'<div class="title">{html.escape(title)}</div>{ds}'
        f'<div class="rule"></div></div>',
        unsafe_allow_html=True)
