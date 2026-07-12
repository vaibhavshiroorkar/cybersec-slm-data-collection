#!/usr/bin/env python3
"""Streamlit-cached wrappers around the expensive read-layer scans.

Walking ``data/raw/`` (100+ GB, hundreds of thousands of files) takes over a
minute, so the results are cached here with ``st.cache_data`` and shared across
every page and rerun. Keyed on the data root so a changed root recomputes. This
module imports Streamlit at the top (unlike :mod:`data`, which stays headless),
so only pages import it.
"""

from __future__ import annotations

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
