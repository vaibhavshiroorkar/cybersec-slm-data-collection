#!/usr/bin/env python3
"""Sourcing (stage 1): discover sources with SearXNG and inspect the catalog.

This page runs the source-discovery stage on its own: pick sub-domains, see every
keyword that will run, tune the caps, and launch. Sub-domains and their keywords
are editable here and persist to ``sources/keywords.yaml`` (shared with the CLI),
so the tool generalizes beyond the built-in cybersecurity taxonomy.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import charts, control, data, settings_store, ui
from cybersec_slm.sourcing import catalog, sheet

ui.inject_css()
ui.stage_header("source", data.stage_states())
st.caption("Discover new sources with SearXNG (`SEARXNG_URL`, default "
           "`http://localhost:8080`) and append them to `sources/Sources.csv`. "
           "Sub-domains and keywords are editable and persist to "
           "`sources/keywords.yaml`.")
st.divider()

cat = catalog.load()
all_domains = catalog.subdomains(cat)

# ------------------------------------------------------------- run discovery ---
st.subheader("Run discovery")
if not all_domains:
    st.info("No sub-domains configured yet. Add one below to get started.")

# Seed the selection from saved source settings so a saved sub-domain / mode
# choice is the starting point (and the same saved settings drive a CLI run).
_saved = settings_store.get_stage("source")
_dom_default = [d for d in _saved.get("domains", []) if d in all_domains] or all_domains
_mode_default = _saved.get("mode", catalog.MODES[0])
_mode_index = catalog.MODES.index(_mode_default) if _mode_default in catalog.MODES else 0

col_a, col_b = st.columns([3, 1])
selected = col_a.multiselect("Sub-domains to search", all_domains,
                             default=_dom_default, key="src_domains")
mode = col_b.selectbox("Mode", catalog.MODES, index=_mode_index, key="src_mode",
                       help="datasets: corpora/repos · text: articles/docs · both")

# Keyword viewer: every keyword that will run for the current selection.
kw_rows = [{"sub-domain": d, "keyword": k, "query": f"{k} ..."}
           for d in selected for k in catalog.keywords_for(d, mode, cat)]
with st.expander(f"Keywords that will run ({len(kw_rows)})",
                 expanded=not selected):
    if kw_rows:
        ui.table([{"sub-domain": r["sub-domain"], "keyword": r["keyword"]}
                  for r in kw_rows], height=300)
    else:
        st.caption("Select at least one sub-domain to see its keywords.")

adv = ui.advanced_settings("source")
settings = {**adv, "domains": selected, "mode": mode}

cstat = control.status()
running = cstat["running"]
c1, c2 = st.columns(2)
if c1.button("▶ Run discovery", disabled=running or not selected,
             use_container_width=True, key="src_run"):
    res = control.start("source", settings=settings)
    if res.get("ok"):
        st.rerun()
    else:
        st.error(res["error"])
if c2.button("⏹ Stop", disabled=not running, use_container_width=True,
             key="src_stop"):
    control.stop()
    st.rerun()
ui.save_settings_button("source", settings, key="source_save")
if running:
    st.caption(f"● running: {cstat.get('stage') or 'pipeline'}  ·  "
               f"pid {cstat['pid']}  ·  started {cstat.get('started_at')}")
else:
    st.caption("Discovery runs as a background process; watch its log on the "
               "Overview page. New rows land in `sources/Sources.csv`.")

# Last-run per-keyword summary (which keywords ran, hits, and new rows kept).
summ = data.latest_source_summary()
if summ:
    with st.expander("Last discovery run"):
        ui.stat_grid([
            ("Hits", charts.fmt_int(summ.get("found"))),
            ("New", charts.fmt_int(summ.get("new"))),
            ("Appended", charts.fmt_int(summ.get("appended"))),
            ("Mode", str(summ.get("mode", ""))),
        ], cols=4)
        bk = summ.get("by_keyword") or []
        if bk:
            st.markdown("**Per keyword**")
            ui.table([{"sub-domain": r.get("domain"), "keyword": r.get("keyword"),
                       "hits": r.get("hits"), "new": r.get("new")} for r in bk],
                     height=300)

st.divider()

# --------------------------------------------------------- edit sub-domains ----
st.subheader("Edit sub-domains & keywords")
with st.expander("Add or replace a sub-domain"):
    name = st.text_input("Sub-domain name", key="add_name")
    ds = st.text_area("Dataset keywords (one per line)", key="add_ds", height=140)
    tx = st.text_area("Text keywords (one per line)", key="add_tx", height=140)
    if st.button("Save sub-domain", key="add_save", disabled=not name.strip()):
        catalog.add_subdomain(
            name.strip(),
            datasets=[ln.strip() for ln in ds.splitlines() if ln.strip()],
            text=[ln.strip() for ln in tx.splitlines() if ln.strip()])
        st.success(f"Saved '{name.strip()}' to sources/keywords.yaml")
        st.rerun()

with st.expander("Remove a sub-domain"):
    if all_domains:
        victim = st.selectbox("Sub-domain to remove", all_domains, key="rm_pick")
        if st.button("Remove", key="rm_go", type="secondary"):
            catalog.remove_subdomain(victim)
            st.success(f"Removed '{victim}' from sources/keywords.yaml")
            st.rerun()
    else:
        st.caption("No sub-domains to remove.")

st.divider()

# ---------------------------------------------------------------- catalog ------
st.subheader("Source catalog")
cat_summary = data.catalog_summary()
ui.stat_grid([
    ("Sources in catalog", charts.fmt_int(cat_summary["total"])),
    ("Sub-domains", charts.fmt_int(len(cat_summary["by_domain"]))),
], cols=2)

st.markdown("**By sub-domain**")
by_dom = [{"sub-domain": k, "sources": v}
          for k, v in sorted(cat_summary["by_domain"].items(),
                             key=lambda kv: kv[1], reverse=True)]
if by_dom:
    ui.table(by_dom, height=280)
else:
    st.caption("No `sources/Sources.csv` found yet.")

st.divider()

# --------------------------------------------------------- delete catalog rows -
st.subheader("Delete catalog rows")
st.caption("Remove rows from `sources/Sources.csv` (deletes instantly). Deleted "
           "sources can be re-discovered; this does not touch already-fetched data.")
cat_rows = data.catalog_rows()
cat_path = data.catalog_path()

_LINK_KEYS = ("dataset link", "url", "link", "dataset_link", "source url")


def _row_link(r: dict) -> str:
    for k, v in r.items():
        if str(k).strip().lower() in _LINK_KEYS:
            return str(v)
    return ""


with st.expander("Delete by sub-domain (group)"):
    dom_opts = sorted(cat_summary["by_domain"].keys())
    victims = st.multiselect("Sub-domains to delete (all their rows)", dom_opts,
                             key="del_domains")
    n = sum(cat_summary["by_domain"].get(d, 0) for d in victims)
    if st.button(f"Delete {n} row(s) in {len(victims)} sub-domain(s)",
                 disabled=not victims, key="del_dom_go", type="secondary"):
        removed = sheet.delete_rows(cat_path, subdomains=victims)
        st.success(f"Deleted {removed} row(s) from the catalog")
        st.rerun()

with st.expander("Delete individual rows"):
    if not cat_rows:
        st.caption("No rows to delete.")
    else:
        labels: list[str] = []
        label_link: dict[str, str] = {}
        for i, r in enumerate(cat_rows):
            link = _row_link(r)
            label = f"{(r.get('Name') or '?')[:40]} · {r.get('Sub-Domain', '')} · {link}"
            if label in label_link:
                label = f"{label}  #{i}"
            label_link[label] = link
            labels.append(label)
        picked = st.multiselect("Rows to delete", labels, key="del_rows")
        if st.button(f"Delete {len(picked)} selected row(s)",
                     disabled=not picked, key="del_rows_go", type="secondary"):
            links = [label_link[la] for la in picked if label_link.get(la)]
            removed = sheet.delete_rows(cat_path, links=links)
            st.success(f"Deleted {removed} row(s) from the catalog")
            st.rerun()

st.divider()

# --------------------------------------------------------------- full table ----
st.subheader("Sources.csv")
rows = data.catalog_rows()
if not rows:
    st.caption("No `sources/Sources.csv` found yet.")
else:
    st.caption(f"{len(rows)} rows")
    ui.table(rows, height=460)
