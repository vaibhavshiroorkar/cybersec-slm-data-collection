#!/usr/bin/env python3
"""Formatting + trend-series helpers for the dashboard pages.

Pure functions (no Streamlit), so they are unit-testable and reusable across
pages. Presentation-only: turning read-layer data into display strings and the
tidy rows the trend charts plot.
"""

from __future__ import annotations


def fmt_int(n) -> str:
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return "-"


def fmt_compact(n) -> str:
    """Compact human count for big display numbers (22,101,118 -> '22.1M')."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "-"
    for div, suf in ((1e9, "B"), (1e6, "M"), (1e3, "K")):
        if abs(n) >= div:
            return f"{n / div:.1f}{suf}".replace(".0" + suf, suf)
    return f"{int(n)}"


def fmt_size(mb) -> str:
    """Human size from a megabyte figure (MB up to 1 GB, then GB / TB)."""
    try:
        mb = float(mb)
    except (TypeError, ValueError):
        return "-"
    if mb >= 1_048_576:
        return f"{mb / 1_048_576:.1f} TB"
    if mb >= 1024:
        return f"{mb / 1024:.1f} GB"
    return f"{mb:.1f} MB"


def fmt_pct(x, digits: int = 1) -> str:
    try:
        return f"{float(x) * 100:.{digits}f}%"
    except (TypeError, ValueError):
        return "-"


def fmt_age(seconds) -> str:
    """Human 'time since' for a run-activity age in seconds."""
    if seconds is None:
        return "never"
    s = int(seconds)
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s // 60}m ago"
    if s < 86400:
        return f"{s // 3600}h ago"
    return f"{s // 86400}d ago"


def fmt_duration(seconds) -> str:
    """Compact ``H:MM:SS`` / ``M:SS`` for an elapsed or remaining duration."""
    try:
        s = int(float(seconds))
    except (TypeError, ValueError):
        return "-"
    if s < 0:
        s = 0
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f"{h}:{m:02d}:{sec:02d}"
    return f"{m}:{sec:02d}"


def fmt_hms(seconds) -> str:
    """Zero-padded ``HH:MM:SS`` for a duration (hours never dropped, e.g. 00:05:23).

    Used for the projected total runtime, where a fixed HH:MM:SS shape reads more
    steadily across refreshes than :func:`fmt_duration`'s variable width.
    """
    try:
        s = int(float(seconds))
    except (TypeError, ValueError):
        return "-"
    if s < 0:
        s = 0
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{sec:02d}"


def eda_trend_rows(history: list[dict]) -> list[dict]:
    """Flatten EDA run history into tidy rows for the trend line charts.

    One row per run: timestamp + the headline metrics. Missing metrics degrade to
    0.0/0 rather than dropping the run, so the series stays aligned.
    """
    rows = []
    for rep in history:
        m = rep.get("metrics", {}) or {}
        drift = m.get("drift", {}) or {}
        rows.append({
            "ts": rep.get("ts"),
            "passed": bool(rep.get("passed")),
            "total": int(m.get("total") or 0),
            "dup_rate": float(m.get("dup_rate") or 0.0),
            "drift": float(drift.get("max_delta") or 0.0),
            "avg_tokens": float((m.get("text_quality") or {}).get("avg_tokens") or 0.0),
            "num_subdomains": int(m.get("num_subdomains") or 0),
        })
    return rows
