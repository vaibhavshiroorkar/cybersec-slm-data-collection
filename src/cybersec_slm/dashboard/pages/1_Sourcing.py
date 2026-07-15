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
from cybersec_slm.sourcing import blacklist, catalog, sheet

ui.inject_css()
ui.page_header("source", data.stage_states())
st.caption("Discover new sources with SearXNG (`SEARXNG_URL`, default "
           "`http://localhost:8080`) and append them to `sources/Sources.csv`.")

cat = catalog.load()
all_domains = catalog.subdomains(cat)
cat_summary = data.catalog_summary()

discover_tab, catalog_tab, licenses_tab, edit_tab, delete_tab, csv_tab = st.tabs(
    ["Discover", "Catalog", "Licenses", "Sub-domains", "Delete rows", "Sources.csv"])

# ============================================================== Discover =======
with discover_tab:
    with ui.section("Keyword preview",
                    "Preview the keywords a discovery run would use. Configure and "
                    "run Sourcing from the Overview page (its Sourcing settings)."):
        if not all_domains:
            st.info("No sub-domains configured yet. Add one in the Sub-domains tab.")

        # Seed the preview from the saved source settings so it reflects what a run
        # launched from the Overview page would search. Read-only: this tab no
        # longer launches discovery.
        _saved = settings_store.get_stage("source")
        _dom_default = [d for d in _saved.get("domains", [])
                        if d in all_domains] or all_domains
        _mode_default = _saved.get("mode", catalog.MODES[0])
        _mode_index = (catalog.MODES.index(_mode_default)
                       if _mode_default in catalog.MODES else 0)

        col_a, col_b = st.columns([3, 1])
        selected = col_a.multiselect("Sub-domains", all_domains,
                                     default=_dom_default, key="src_domains")
        mode = col_b.selectbox(
            "Mode", catalog.MODES, index=_mode_index, key="src_mode",
            help="datasets: corpora/repos · text: articles/docs · both")

        kw_rows = [{"sub-domain": d, "keyword": k}
                   for d in selected for k in catalog.keywords_for(d, mode, cat)]
        with st.expander(f"Keywords that will run ({len(kw_rows)})",
                         expanded=not selected):
            if kw_rows:
                ui.table(kw_rows, height=300)
            else:
                st.caption("Select at least one sub-domain to see its keywords.")
        st.caption("This preview is read-only. Set the sub-domains, mode, and caps "
                   "for an actual run in the Overview page's Sourcing settings.")

    summ = data.latest_source_summary()
    if summ:
        with ui.section("Last discovery run"):
            _rate = float(summ.get("license_rate") or 0.0)
            ui.stat_grid([
                ("New", charts.fmt_int(summ.get("new"))),
                ("Licensed", f"{charts.fmt_int(summ.get('license_filled'))} "
                             f"({_rate:.0%})"),
                ("Appended", charts.fmt_int(summ.get("appended"))),
                ("Elapsed", f"{summ.get('elapsed_s', 0)}s"),
            ], cols=4)
            _mode = str(summ.get("mode", ""))
            _mm = summ.get("max_minutes")
            st.caption(f"Mode: {_mode}  ·  {charts.fmt_int(summ.get('found'))} hits"
                       + (f"  ·  budget {_mm} min" if _mm else ""))
            bk = summ.get("by_keyword") or []
            if bk:
                st.markdown("**Per keyword**")
                ui.table([{"sub-domain": r.get("domain"), "keyword": r.get("keyword"),
                           "hits": r.get("hits"), "new": r.get("new")} for r in bk],
                         height=300)

# =============================================================== Catalog =======
with catalog_tab:
    with ui.section("Source catalog"):
        ui.stat_grid([
            ("Sources in catalog", charts.fmt_int(cat_summary["total"])),
            ("Sub-domains", charts.fmt_int(len(cat_summary["by_domain"]))),
        ], cols=2)

        st.markdown("**By sub-domain**")
        by_dom = [{"sub-domain": k, "sources": v}
                  for k, v in sorted(cat_summary["by_domain"].items(),
                                     key=lambda kv: kv[1], reverse=True)]
        if by_dom:
            ui.table(by_dom, height=360)
        else:
            st.caption("No `sources/Sources.csv` found yet.")

# =============================================================== Licenses ======
with licenses_tab:
    cov = data.license_coverage()
    bl = data.blacklist_summary()

    running = control.status()["running"]

    with ui.section("License coverage",
                    "Deep-detect the license for each source from its page "
                    "(GitHub, Kaggle, arXiv, HuggingFace, and generic HTML), then "
                    "move confirmed-restrictive sources to the blacklist."):
        ui.stat_grid([
            ("Sources", charts.fmt_int(cov["total"])),
            ("Licensed", charts.fmt_int(cov["filled"])),
            ("Unknown / blank", charts.fmt_int(cov["unknown"])),
            ("Blacklisted", charts.fmt_int(bl["total"])),
        ], cols=4)
        st.caption("Run a full license backfill from the command line: "
                   "`cybersec-slm source --backfill` (set `GITHUB_TOKEN` first for "
                   "full GitHub coverage). The instant tools below need no run.")

    with ui.section("Clean up by license",
                    "Act on `sources/Sources.csv` instantly, no run needed. Deleted "
                    "sources can be re-discovered; already-fetched data is untouched."):
        blank_links = data.blank_license_links()
        b1, b2 = st.columns(2)
        if b1.button(f"Blacklist {cov['red']} confirmed-red source(s)",
                     disabled=running or not cov["red"], type="secondary",
                     use_container_width=True, key="lic_bl_reds"):
            res = blacklist.move_flagged(data.catalog_path())
            st.success(f"Moved {res['moved']} restrictive source(s) to Blacklist.csv")
            st.rerun()
        if b2.button(f"Delete {len(blank_links)} blank-license source(s)",
                     disabled=running or not blank_links, type="secondary",
                     use_container_width=True, key="lic_del_blank"):
            removed = sheet.delete_rows(data.catalog_path(), links=blank_links)
            st.success(f"Deleted {removed} source(s) with no resolved license")
            st.rerun()
        st.caption("Confirmed-red = copyleft / non-commercial / proprietary "
                   "(never commercially trainable). Blank = license not yet "
                   "detected; run Backfill first if you want a chance to resolve them.")

    with ui.section("Blacklist",
                    "Sources with a confirmed-restrictive license, moved out of "
                    "`sources/Sources.csv` to `sources/Blacklist.csv`."):
        if not bl["total"]:
            st.caption("No blacklisted sources yet.")
        else:
            st.markdown("**By reason**")
            ui.table([{"reason": k, "sources": v}
                      for k, v in sorted(bl["by_reason"].items(),
                                         key=lambda kv: kv[1], reverse=True)],
                     height=200)
            ui.table(data.blacklist_rows(), height=360)

# ============================================================= Sub-domains =====
with edit_tab:
    with ui.section("Corpus taxonomy",
                    "The top-level `domain_name` schema label this whole corpus "
                    "is filed under (default `CYBERSEC`). Shared by the schema "
                    "stage — change it once here to repoint the pipeline at a "
                    "different data domain."):
        dn = st.text_input("Domain name", value=catalog.domain_name(),
                           key="domain_name_input")
        if ui.right_slot().button("Save domain name", key="domain_name_save",
                                  disabled=not dn.strip(),
                                  use_container_width=True):
            catalog.set_domain_name(dn.strip())
            st.success(f"Saved domain_name='{dn.strip()}' to sources/keywords.yaml")
            st.rerun()

    with ui.section("Add or replace a sub-domain",
                    "Sub-domains and keywords persist to `sources/keywords.yaml`."):
        name = st.text_input("Sub-domain name", key="add_name")
        code = st.text_input(
            "Enum code (blank = auto-derived from the name)", key="add_code",
            help="The schema's `subdomain_name` enum value for this sub-domain, "
                 "e.g. `APPLICATION`. Leave blank to derive one automatically.")
        ds = st.text_area("Dataset keywords (one per line)", key="add_ds", height=140)
        tx = st.text_area("Text keywords (one per line)", key="add_tx", height=140)
        if ui.right_slot().button("Save sub-domain", key="add_save",
                                  disabled=not name.strip(),
                                  use_container_width=True):
            catalog.add_subdomain(
                name.strip(),
                datasets=[ln.strip() for ln in ds.splitlines() if ln.strip()],
                text=[ln.strip() for ln in tx.splitlines() if ln.strip()],
                code=code.strip() or None)
            st.success(f"Saved '{name.strip()}' to sources/keywords.yaml")
            st.rerun()

    with ui.section("Remove a sub-domain"):
        if all_domains:
            victim = st.selectbox("Sub-domain to remove", all_domains, key="rm_pick")
            if st.button("Remove", key="rm_go", type="secondary"):
                catalog.remove_subdomain(victim)
                st.success(f"Removed '{victim}' from sources/keywords.yaml")
                st.rerun()
        else:
            st.caption("No sub-domains to remove.")

# ============================================================= Delete rows =====
with delete_tab:
    cat_rows = data.catalog_rows()
    cat_path = data.catalog_path()
    _LINK_KEYS = ("dataset link", "url", "link", "dataset_link", "source url")

    def _row_link(r: dict) -> str:
        for k, v in r.items():
            if str(k).strip().lower() in _LINK_KEYS:
                return str(v)
        return ""

    with ui.section("Delete catalog rows",
                    "Removes rows from `sources/Sources.csv` instantly. Deleted "
                    "sources can be re-discovered; already-fetched data is untouched."):
        with st.expander("Delete by sub-domain (group)"):
            dom_opts = sorted(cat_summary["by_domain"].keys())
            victims = st.multiselect("Sub-domains to delete (all their rows)",
                                     dom_opts, key="del_domains")
            n = sum(cat_summary["by_domain"].get(d, 0) for d in victims)
            if st.button(f"Delete {n} row(s) in {len(victims)} sub-domain(s)",
                         disabled=not victims, key="del_dom_go", type="secondary"):
                removed = sheet.delete_rows(cat_path, subdomains=victims)
                st.success(f"Deleted {removed} row(s) from the catalog")
                st.rerun()

        with st.expander("Delete by row range"):
            total = len(cat_rows)
            if not total:
                st.caption("No rows to delete.")
            else:
                st.caption(f"Rows are numbered 1 to {total} in Sources.csv order "
                           "(same order as the Sources.csv tab).")
                c1, c2 = st.columns(2)
                start = c1.number_input("From row", min_value=1, max_value=total,
                                        value=1, step=1, key="del_range_start")
                to_last = st.checkbox("To last row", value=True, key="del_range_last")
                end = c2.number_input("To row", min_value=1, max_value=total,
                                      value=total, step=1, disabled=to_last,
                                      key="del_range_end")
                end_val = total if to_last else int(end)
                start_val = int(start)
                valid = start_val <= end_val
                count = (end_val - start_val + 1) if valid else 0
                if not valid:
                    st.warning("'From row' must be less than or equal to 'To row'.")
                if st.button(f"Delete rows {start_val} to {end_val} "
                             f"({count} row(s))", disabled=not valid,
                             key="del_range_go", type="secondary"):
                    positions = list(range(start_val, end_val + 1))
                    removed = sheet.delete_rows(cat_path, positions=positions)
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
                    label = (f"{(r.get('Name') or '?')[:40]} · "
                             f"{r.get('Sub-Domain', '')} · {link}")
                    if label in label_link:
                        label = f"{label}  #{i}"
                    label_link[label] = link
                    labels.append(label)
                picked = st.multiselect("Rows to delete", labels, key="del_rows")
                if st.button(f"Delete {len(picked)} selected row(s)",
                             disabled=not picked, key="del_rows_go",
                             type="secondary"):
                    links = [label_link[la] for la in picked if label_link.get(la)]
                    removed = sheet.delete_rows(cat_path, links=links)
                    st.success(f"Deleted {removed} row(s) from the catalog")
                    st.rerun()

# ============================================================= Sources.csv =====
with csv_tab:
    with ui.section("Sources.csv"):
        rows = data.catalog_rows()
        if not rows:
            st.caption("No `sources/Sources.csv` found yet.")
        else:
            st.caption(f"{len(rows)} rows")
            ui.table(rows, height=520)
