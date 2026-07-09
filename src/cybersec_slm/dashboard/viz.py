#!/usr/bin/env python3
"""Altair chart builders for the dashboard, styled to the console theme.

Presentation layer (imports altair). Each function returns a configured
``alt.Chart`` (or ``None`` when there's nothing to plot) so pages just call
``st.altair_chart(..., use_container_width=True)``. Kept apart from the tested,
Streamlit-free read layer.
"""

from __future__ import annotations

import altair as alt

_MUTED = "#8A9BB0"
_LINE = "#263447"
_GRID = "#1C2838"
_INK = "#E6EDF5"
_SERIES = ["#38BDF8", "#A78BFA", "#34D399", "#FBBF24", "#F87171"]


def _base(chart: alt.Chart, height: int) -> alt.Chart:
    """Apply the shared dark, gridline-light instrument styling."""
    return (chart.properties(height=height, background="transparent")
            .configure_view(strokeWidth=0)
            .configure_axis(labelColor=_MUTED, titleColor=_MUTED, domainColor=_LINE,
                            gridColor=_GRID, tickColor=_LINE, labelFont="JetBrains Mono",
                            titleFont="Inter", labelFontSize=11, titleFontSize=11)
            .configure_legend(labelColor=_MUTED, titleColor=_MUTED, labelFont="Inter"))


def domain_bar(by_domain: dict, value_label: str = "sources"):
    """Horizontal ranked bar of counts per domain (sequential shade by value)."""
    if not by_domain:
        return None
    data = [{"domain": k, "count": v} for k, v in by_domain.items()]
    chart = (alt.Chart(alt.Data(values=data))
             .mark_bar(cornerRadiusEnd=3, height={"band": 0.72})
             .encode(
                 y=alt.Y("domain:N", sort="-x", title=None,
                         axis=alt.Axis(labelLimit=220)),
                 x=alt.X("count:Q", title=value_label,
                         axis=alt.Axis(grid=True, tickCount=5)),
                 color=alt.Color("count:Q", scale=alt.Scale(scheme="tealblues"),
                                 legend=None),
                 tooltip=[alt.Tooltip("domain:N", title="domain"),
                          alt.Tooltip("count:Q", title=value_label)]))
    return _base(chart, height=max(220, 26 * len(data)))


def funnel_bar(stages: list[dict]):
    """Horizontal bars for the Raw -> Cleaned -> Final record funnel.

    ``stages``: ``[{"stage": "Raw", "lines": int, "color": hex}, ...]``.
    """
    data = [s for s in stages if s.get("lines")]
    if not data:
        return None
    order = [s["stage"] for s in stages]
    chart = (alt.Chart(alt.Data(values=data))
             .mark_bar(cornerRadiusEnd=3, height={"band": 0.6})
             .encode(
                 y=alt.Y("stage:N", sort=order, title=None),
                 x=alt.X("lines:Q", title="records", axis=alt.Axis(grid=True)),
                 color=alt.Color("stage:N", sort=order,
                                 scale=alt.Scale(domain=order, range=_SERIES[:len(order)]),
                                 legend=None),
                 tooltip=[alt.Tooltip("stage:N"), alt.Tooltip("lines:Q", title="records")]))
    return _base(chart, height=max(160, 46 * len(data)))


def trend_lines(rows: list[dict], series: list[tuple[str, str]], x: str = "ts"):
    """Multi-series line chart over EDA run history.

    ``series``: list of ``(field, label)`` to plot as separate coloured lines.
    """
    if len(rows) < 2:
        return None
    long = []
    for i, r in enumerate(rows):
        xv = r.get(x) or i
        for field, label in series:
            long.append({"x": str(xv), "i": i, "metric": label,
                         "value": float(r.get(field) or 0.0)})
    labels = [lbl for _, lbl in series]
    chart = (alt.Chart(alt.Data(values=long))
             .mark_line(point=True, strokeWidth=2)
             .encode(
                 x=alt.X("i:O", title=None, axis=alt.Axis(labels=False, ticks=False)),
                 y=alt.Y("value:Q", title=None, axis=alt.Axis(grid=True)),
                 color=alt.Color("metric:N", scale=alt.Scale(domain=labels, range=_SERIES),
                                 legend=alt.Legend(orient="top", title=None)),
                 tooltip=["metric:N", alt.Tooltip("value:Q", format=".3f")]))
    return _base(chart, height=240)
