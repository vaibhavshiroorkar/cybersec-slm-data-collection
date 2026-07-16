#!/usr/bin/env python3
"""Streamlit-cached wrappers around the expensive read-layer scans.

Walking ``data/raw/`` (100+ GB, hundreds of thousands of files) takes over a
minute, so the results are cached here with ``st.cache_data`` and shared across
every page and rerun. Keyed on the data root so a changed root recomputes. This
module imports Streamlit at the top (unlike :mod:`data`, which stays headless),
so only pages import it.
"""

from __future__ import annotations

import os

import streamlit as st

from . import data

# Long TTL: the raw tree only changes when ingestion runs, so one measurement
# per dashboard session is plenty. The user can hard-refresh to remeasure.
_RAW_TTL_S = 3600


@st.cache_data(ttl=_RAW_TTL_S, show_spinner="Measuring data/raw on disk (one-time)...")
def raw_table(root: str) -> list[dict]:
    """Cached per-source raw folder table (see :func:`data.raw_table`)."""
    return data.raw_table()


def raw_size_mb(root: str) -> float:
    """Total on-disk size of ``data/raw/`` in MB, from the cached folder walk."""
    return sum(r["size_mb"] for r in raw_table(root))


# The corpus funnel scans data/ (records + sizes) on every full rerun, which made
# the Overview flash and recompute on each interaction. Cache it on a short TTL so
# it renders from a stable snapshot; a run or the manual Refresh button clears it.
_STATS_TTL_S = 90


@st.cache_data(ttl=_STATS_TTL_S, show_spinner=False)
def funnel(root: str) -> dict:
    """Cached corpus-funnel snapshot: ``{funnel, progress}`` (see :mod:`data`)."""
    f = data.data_funnel()
    f["raw"]["size_mb"] = raw_size_mb(root)
    return {"funnel": f, "progress": data.ingest_progress()}


@st.cache_data(ttl=_STATS_TTL_S, show_spinner=False)
def data_funnel(root: str) -> dict:
    """Cached wrapper around :func:`data.data_funnel` (Ingest/Clean/Schema pages)."""
    return data.data_funnel()


# Live-ish cleaned record count: the clean report is only written when a clean
# pass finishes, so during a run the funnel would show 0 (or a stale total). Count
# the JSONL records physically under data/clean on a short TTL so the Overview shows
# the cleaned total growing as workers write, without scanning on every 1s tick.
_CLEAN_RECORDS_TTL_S = 20


@st.cache_data(ttl=_CLEAN_RECORDS_TTL_S, show_spinner=False)
def cleaned_records(root: str) -> int:
    """Records currently under ``data/clean`` (cheap short-TTL live count)."""
    return data._count_jsonl_records(os.path.join(root, "data", "clean"))


@st.cache_data(ttl=_STATS_TTL_S, show_spinner=False)
def cleaned_table(root: str) -> list[dict]:
    """Cached per-source cleaned-folder table (:func:`data.cleaned_table`).

    Walks every ``data/clean/<domain>/<source>/`` folder and opens every JSONL
    file to count lines - expensive at hundreds of folders, so it shares the
    funnel's short TTL rather than running uncached on every page rerun.
    """
    return data.cleaned_table()


@st.cache_data(ttl=_STATS_TTL_S, show_spinner=False)
def ingest_table(root: str) -> list[dict]:
    """Cached full per-source ingest table (:func:`data.ingest_table`).

    Parses the catalog into descriptors and reconciles each against ``data/raw/``,
    so it shares the funnel's TTL rather than rerunning on every interaction. The
    on-disk byte figures come from the already-cached :func:`raw_table` walk, so
    this adds no second scan of the raw tree.
    """
    return data.ingest_table(raw_rows=raw_table(root))


def clear_stats() -> None:
    """Drop every cached scan snapshot so the next read remeasures."""
    funnel.clear()
    raw_table.clear()
    data_funnel.clear()
    cleaned_records.clear()
    cleaned_table.clear()
    ingest_table.clear()
