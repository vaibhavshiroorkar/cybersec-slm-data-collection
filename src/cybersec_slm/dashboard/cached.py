#!/usr/bin/env python3
"""Streamlit-cached wrappers around the expensive read-layer scans.

Walking ``data/raw/`` (100+ GB, hundreds of thousands of files) takes over a
minute, so the results are cached here with ``st.cache_data`` and shared across
every page and rerun.

Keyed on :func:`data.scope`, which is the data root *and* the active profile.
Keying on the root alone made the cache a second way to show the wrong corpus:
both profiles live under one root, so switching to ubi re-read nothing and served
cybersec's cached counts under ubi's name. Every ``scope`` parameter below is a
cache key and nothing else; the paths are resolved live from the active profile.

This module imports Streamlit at the top (unlike :mod:`data`, which stays
headless), so only pages import it.
"""

from __future__ import annotations

import os

import streamlit as st

from . import data
from . import final_stats as _final_stats

# Long TTL: the raw tree only changes when ingestion runs, so one measurement
# per dashboard session is plenty. The user can hard-refresh to remeasure.
_RAW_TTL_S = 3600


@st.cache_data(ttl=_RAW_TTL_S, show_spinner="Measuring data/raw on disk (one-time)...")
def raw_table(scope: str) -> list[dict]:
    """Cached per-source raw folder table (see :func:`data.raw_table`)."""
    return data.raw_table()


def raw_size_mb(scope: str) -> float:
    """Total on-disk size of ``data/raw/`` in MB, from the cached folder walk."""
    return sum(r["size_mb"] for r in raw_table(scope))


@st.cache_data(ttl=_RAW_TTL_S, show_spinner="Counting data/raw records (one-time)...")
def raw_records(scope: str) -> int:
    """Records physically under ``data/raw/`` (the funnel's Raw "Records").

    Counted rather than read off the catalog: the catalog's ``Total Lines``
    understated the live corpus by 149% (17,972,727 claimed vs 44,761,032 on
    disk) and had no figure at all for 242 of the 370 fetched sources. Reading
    ~90 GB of JSONL takes a couple of minutes cold, which is why it shares
    ``raw_table``'s long TTL — raw only changes when ingestion runs, and the
    per-file counts are memoized by (mtime, size), so a re-count after a run only
    re-reads the files that actually changed.
    """
    return data._count_jsonl_records(data._raw())


# The corpus funnel scans data/ (records + sizes) on every full rerun, which made
# the Overview flash and recompute on each interaction. Cache it on a short TTL so
# it renders from a stable snapshot; a run or the manual Refresh button clears it.
_STATS_TTL_S = 90


@st.cache_data(ttl=_STATS_TTL_S, show_spinner=False)
def funnel(scope: str) -> dict:
    """Cached corpus-funnel snapshot: ``{funnel, progress}`` (see :mod:`data`).

    Raw size and records both come from the long-TTL scans rather than this
    snapshot's own walk, so the expensive measurements are shared and paid once.
    """
    f = data.data_funnel()
    f["raw"]["size_mb"] = raw_size_mb(scope)
    f["raw"]["lines"] = raw_records(scope)
    return {"funnel": f, "progress": data.ingest_progress()}


@st.cache_data(ttl=_STATS_TTL_S, show_spinner=False)
def data_funnel(scope: str) -> dict:
    """Cached wrapper around :func:`data.data_funnel` (Ingest/Clean/Schema pages)."""
    return data.data_funnel()


# Live-ish cleaned record count: the clean report is only written when a clean
# pass finishes, so during a run the funnel would show 0 (or a stale total). Count
# the JSONL records physically under data/clean on a short TTL so the Overview shows
# the cleaned total growing as workers write, without scanning on every 1s tick.
_CLEAN_RECORDS_TTL_S = 20


@st.cache_data(ttl=_CLEAN_RECORDS_TTL_S, show_spinner=False)
def cleaned_records(scope: str) -> int:
    """Records currently under ``data/clean`` (cheap short-TTL live count)."""
    return data._count_jsonl_records(data._clean())


@st.cache_data(ttl=_CLEAN_RECORDS_TTL_S,
               show_spinner="Counting data/final records (one-time)...")
def final_stats(scope: str) -> dict:
    """Records / sources / tokens / size of ``data/final/dataset.jsonl``.

    Shares the cleaned count's short TTL for the same reason: the final dataset
    grows live as normalize appends to it, and its manifest only lands when the
    pass finishes. Returned as a plain dict because ``st.cache_data`` pickles its
    values, and callers only read fields.

    The scan underneath is incremental, so this TTL bounds how often a tick pays
    for the few MB appended since the last one, not a re-read of the whole corpus.
    Only the very first scan reads the lot (about 17s at 5 GB), which is why this
    one shows a spinner while the short-TTL refreshes stay silent.
    """
    fs = _final_stats.scan(os.path.join(data._final(), "dataset.jsonl"))
    return {"sources": fs.sources, "lines": fs.records, "tokens": fs.tokens,
            "size_mb": fs.size_mb}


@st.cache_data(ttl=_STATS_TTL_S, show_spinner=False)
def cleaned_table(scope: str) -> list[dict]:
    """Cached per-source cleaned-folder table (:func:`data.cleaned_table`).

    Walks every ``data/clean/<domain>/<source>/`` folder and opens every JSONL
    file to count lines - expensive at hundreds of folders, so it shares the
    funnel's short TTL rather than running uncached on every page rerun.
    """
    return data.cleaned_table()


@st.cache_data(ttl=_STATS_TTL_S, show_spinner=False)
def ingest_table(scope: str) -> list[dict]:
    """Cached full per-source ingest table (:func:`data.ingest_table`).

    Parses the catalog into descriptors and reconciles each against ``data/raw/``,
    so it shares the funnel's TTL rather than rerunning on every interaction. The
    on-disk byte figures come from the already-cached :func:`raw_table` walk, so
    this adds no second scan of the raw tree.
    """
    return data.ingest_table(raw_rows=raw_table(scope))


def clear_stats() -> None:
    """Drop every cached scan snapshot so the next read remeasures."""
    funnel.clear()
    raw_table.clear()
    raw_records.clear()
    data_funnel.clear()
    cleaned_records.clear()
    final_stats.clear()
    cleaned_table.clear()
    ingest_table.clear()
    # The scan memo is keyed on byte offsets in dataset.jsonl, so a Reset that
    # deletes data/ must drop it too; otherwise the next scan would resume from an
    # offset into a file that no longer exists.
    _final_stats.reset()
