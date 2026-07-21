#!/usr/bin/env python3
"""Schema (stage 5): the release dataset, its manifest, and a corpus browser.

Read-only. Re-run normalize and watch the log from the Overview page; every value
here comes from :mod:`cybersec_slm.dashboard.data`.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import cached, charts, data, schema_store, ui

PAGE_SIZE = 50
_SNIPPET = 160
_TABLE_FIELDS = ("id", "source", "subdomain_name", "record_type", "token_count", "lang")

ui.inject_css()
ui.page_header("schema", data.stage_states())
st.caption("Cleaned records mapped onto the canonical schema in "
           "`data/final/dataset.jsonl`, with a provenance manifest.")

man = data.manifest()
norm_tab, fields_tab, manifest_tab, browse_tab = st.tabs(
    ["Normalize", "Fields", "Manifest", "Browse"])

# ------------------------------------------------------------- normalize -------
with norm_tab:
    with ui.section("Normalization"):
        appended = cached.data_funnel(data.scope())["appended"]
        c = st.columns(4)
        c[0].metric("Sources", charts.fmt_int(appended["sources"]))
        c[1].metric("Records written", charts.fmt_int(appended["lines"]))
        c[2].metric("Size", charts.fmt_size(appended["size_mb"]))
        # Summed from each record's token_count as the dataset is scanned, not read
        # off the manifest: the manifest only exists once a normalize pass has
        # finished, and this number is wanted most while one is still running.
        c[3].metric("Tokens", charts.fmt_int(appended["tokens"]),
                    help="Total tokens across `data/final/dataset.jsonl`, summed "
                         "from every record's `token_count`.")

        nr = data.normalize_report()
        if nr:
            with st.expander("Normalization breakdown"):
                st.write(nr.get("counts", {}))
                if nr.get("paused_sources"):
                    st.warning(f"paused sources: {', '.join(nr['paused_sources'])}")
        else:
            st.caption("No normalize report yet.")

# --------------------------------------------------------------- fields --------
with fields_tab:
    with ui.section("Canonical schema fields",
                    "The 22-field record contract. Type and requiredness come from "
                    "the model; edit a field's default or description and save. "
                    "Edits annotate the catalog only — validation is unchanged."):
        import pandas as pd

        df = pd.DataFrame(schema_store.field_catalog())
        edited = st.data_editor(
            df, width='stretch', hide_index=True,
            key="schema_fields_editor", disabled=("field", "type", "required"),
            column_config={
                "field": st.column_config.TextColumn("field", width="medium"),
                "type": st.column_config.TextColumn("type"),
                "required": st.column_config.CheckboxColumn("required"),
                "default": st.column_config.TextColumn("default"),
                "description": st.column_config.TextColumn(
                    "description", width="large"),
            })
        if ui.right_slot().button("Save fields", key="schema_fields_save",
                                  width='stretch'):
            schema_store.save_overrides(edited.to_dict("records"))
            st.toast("Saved schema field edits")

# ------------------------------------------------------------- manifest --------
with manifest_tab:
    with ui.section("Release manifest"):
        if not man:
            st.caption("No manifest yet (`data/final/manifest.json`). Run this "
                       "stage from the Overview page.")
        else:
            ui.stat_grid([
                ("Records", charts.fmt_int(man.get("record_count"))),
                ("Unique hashes", charts.fmt_int(man.get("unique_content_hashes"))),
                ("Tokens", charts.fmt_int(man.get("token_total"))),
            ], cols=3)
            st.caption(f"pipeline {man.get('pipeline_version')}  ·  git "
                       f"{(man.get('git_commit') or '')[:10]}  ·  sha256 "
                       f"{(man.get('dataset_sha256') or '')[:12]}")
            d = st.columns(2)
            d[0].markdown("**By domain**")
            d[0].write(man.get("domains", {}))
            d[1].markdown("**By license**")
            d[1].write(man.get("licenses", {}))

            src = man.get("sources", {}) or {}
            if src:
                st.markdown("**Records by source**")
                rows = [{"source": k, "records": v}
                        for k, v in sorted(src.items(), key=lambda kv: kv[1],
                                           reverse=True)]
                ui.table(rows, height=300)

# --------------------------------------------------------------- browse --------
with browse_tab:
    with ui.section("Browse the corpus"):
        if man:
            a, b, cc = st.columns(3)
            a.metric("Records", charts.fmt_int(man.get("record_count")))
            b.metric("Subdomains", charts.fmt_int(len(man.get("subdomains") or {})))
            cc.metric("Sources", charts.fmt_int(len(man.get("sources") or {})))

        facets = data.dataset_facets()
        filters: dict[str, str] = {}
        fcols = st.columns(len(data.FILTER_FIELDS))
        for i, ui_field in enumerate(data.FILTER_FIELDS):
            values = sorted((facets.get(ui_field) or {}).keys())
            choice = fcols[i].selectbox(ui_field, ["(all)"] + values,
                                        key=f"flt_{ui_field}")
            if choice != "(all)":
                filters[ui_field] = choice
        search = st.text_input("Search text",
                               placeholder="case-insensitive substring...")

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
        st.caption(
            f"showing {shown_lo} to {shown_hi} of {result['match_count']}{more} "
            f"matches" + (f"  ·  scan capped at {data.DATASET_SCAN_CAP:,} records"
                          if result["capped"] else ""))

        if not rows:
            st.info("No matching records (or no `data/final/dataset.jsonl` yet).")
        else:
            table = [{**{f: r.get(f) for f in _TABLE_FIELDS},
                      "text": (r.get("text") or "")[:_SNIPPET]} for r in rows]
            ui.table(table)

            nav = st.columns([1, 1, 6])
            if nav[0].button("prev", disabled=offset == 0):
                st.session_state["_ds_offset"] = max(0, offset - PAGE_SIZE)
                st.rerun()
            if nav[1].button("next", disabled=len(rows) < PAGE_SIZE):
                st.session_state["_ds_offset"] = offset + PAGE_SIZE
                st.rerun()

            st.markdown("**Record detail**")
            ids = [r.get("id") for r in rows]
            picked = st.selectbox("record id", ids)
            detail = next((r for r in rows if r.get("id") == picked), None)
            if detail:
                st.json(detail)

    with ui.section("What didn't make it"):
        subtabs = st.tabs(["Rejected", "Duplicates", "Near-dup scores"])
        for tab, kind in zip(subtabs, ("rejected", "duplicates", "dedup_scores"),
                             strict=True):
            with tab:
                preview = data.sidecar(kind, limit=100)
                if preview:
                    ui.table(preview)
                else:
                    st.caption(f"No `{kind}` records.")
