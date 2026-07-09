#!/usr/bin/env python3
"""Dataset page - search / filter / browse the final corpus + what didn't make it.

Presentation only; every value comes from :mod:`cybersec_slm.dashboard.data`.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import charts, data, theme

st.set_page_config(page_title="Dataset · cybersec-slm", page_icon="🛡️", layout="wide")
theme.inject()

PAGE_SIZE = 50
_SNIPPET = 160
_TABLE_FIELDS = ("id", "source", "subdomain_name", "record_type", "token_count", "lang")

man = data.manifest()
theme.hero("Dataset", "explore · filter · inspect",
           "search and page through the released corpus, and the records that "
           "did not make it in")

if man:
    theme.kpi_grid([
        {"label": "records", "value": charts.fmt_int(man.get("record_count")),
         "status": "pass"},
        {"label": "subdomains", "value": charts.fmt_int(len(man.get("subdomains") or {})),
         "status": "accent"},
        {"label": "sources", "value": charts.fmt_int(len(man.get("sources") or {}))},
        {"label": "tokens", "value": charts.fmt_int(man.get("token_total"))},
    ])
else:
    st.info("No released corpus yet (`data/final/dataset.jsonl`). Run the pipeline first.")

# ------------------------------------------------------------------- filters ---
theme.section("Browse", eyebrow="filter + search")
facets = data.dataset_facets()
filters: dict[str, str] = {}
fcols = st.columns(len(data.FILTER_FIELDS))
for i, ui_field in enumerate(data.FILTER_FIELDS):
    values = sorted((facets.get(ui_field) or {}).keys())
    choice = fcols[i].selectbox(ui_field, ["(all)"] + values, key=f"flt_{ui_field}")
    if choice != "(all)":
        filters[ui_field] = choice
search = st.text_input("Search text", placeholder="case-insensitive substring…")

# Reset paging whenever the query changes.
query_key = (tuple(sorted(filters.items())), search.strip().lower())
if st.session_state.get("_ds_query") != query_key:
    st.session_state["_ds_query"] = query_key
    st.session_state["_ds_offset"] = 0
offset = st.session_state.get("_ds_offset", 0)

result = data.dataset_page(filters, search, offset=offset, limit=PAGE_SIZE)
rows = result["rows"]
shown_lo = offset + 1 if rows else 0
shown_hi = offset + len(rows)
more = "+" if result["capped"] else ""
st.caption(f"showing {shown_lo}–{shown_hi} of {result['match_count']}{more} matches"
           + (f"  ·  scan capped at {data.DATASET_SCAN_CAP:,} records"
              if result["capped"] else ""))

if not rows:
    st.info("No matching records (or no `data/final/dataset.jsonl` yet).")
else:
    table = [{**{f: r.get(f) for f in _TABLE_FIELDS},
              "text": (r.get("text") or "")[:_SNIPPET]} for r in rows]
    st.dataframe(table, use_container_width=True, hide_index=True)

    nav = st.columns([1, 1, 6])
    if nav[0].button("◀ prev", disabled=offset == 0):
        st.session_state["_ds_offset"] = max(0, offset - PAGE_SIZE)
        st.rerun()
    if nav[1].button("next ▶", disabled=len(rows) < PAGE_SIZE):
        st.session_state["_ds_offset"] = offset + PAGE_SIZE
        st.rerun()

    theme.section("Record detail", eyebrow="inspect")
    ids = [r.get("id") for r in rows]
    picked = st.selectbox("record id", ids)
    detail = next((r for r in rows if r.get("id") == picked), None)
    if detail:
        st.json(detail)

# --------------------------------------------------------- what didn't make it -
theme.section("What didn't make it", eyebrow="rejected + de-duplicated",
              desc="a preview of records dropped on the way into the corpus")
tabs = st.tabs(["Rejected", "Duplicates", "Near-dup scores"])
for tab, kind in zip(tabs, ("rejected", "duplicates", "dedup_scores"), strict=True):
    with tab:
        preview = data.sidecar(kind, limit=100)
        if preview:
            st.dataframe(preview, use_container_width=True, hide_index=True)
        else:
            st.caption(f"No `{kind}` records.")
