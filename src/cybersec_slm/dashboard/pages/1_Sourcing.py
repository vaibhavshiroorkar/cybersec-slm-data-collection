#!/usr/bin/env python3
"""Sourcing (stage 1): curate the taxonomy and the source catalog.

Everything that decides *what* discovery looks for, and *what* the catalog holds,
is edited here; the run itself is launched from the Overview page.

    Discover     pick the sub-domains + mode a run searches, and Apply to save
                 them (they persist to ``pipeline_settings.json``); preview the
                 keywords those choices produce
    Sub-domains  add / edit / rename / remove sub-domains and their keywords,
                 persisted to the profile's ``keywords.yaml`` (shared with the CLI)
    Add source   append a source to the profile's ``Sources.csv`` by hand
    Licenses     resolve licenses and blacklist the confirmed-restrictive ones
    Delete rows  remove catalog rows by sub-domain, range, or individually

The taxonomy lives entirely in ``keywords.yaml`` — sub-domain names, their schema
enum codes, and the top-level ``domain_name`` — so the tool generalizes beyond the
built-in cybersecurity taxonomy: repoint that file and the whole pipeline follows.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import charts, control, data, settings_store, ui
from cybersec_slm.sourcing import blacklist, catalog, sheet
from cybersec_slm.sourcing import row as row_builder

ui.inject_css()
ui.page_header("source", data.stage_states())
st.caption("Discover new sources with SearXNG (`SEARXNG_URL`, default "
           "`http://localhost:8080`) and append them to the profile's `Sources.csv`.")

cat = catalog.load()
all_domains = catalog.subdomains(cat)
cat_summary = data.catalog_summary()

(discover_tab, catalog_tab, licenses_tab, edit_tab, add_tab, delete_tab,
 csv_tab) = st.tabs(["Discover", "Catalog", "Licenses", "Sub-domains",
                     "Add source", "Delete rows", "Sources.csv"])

# ============================================================== Discover =======
with discover_tab:
    with ui.section("Sub-domains to search",
                    "Pick the sub-domains and mode a discovery run should use, "
                    "then Apply to save them. The saved selection drives both the "
                    "Sourcing stage's own run and the full pipeline run launched "
                    "from the Overview page."):
        if not all_domains:
            st.info("No sub-domains configured yet. Add one in the Sub-domains tab.")

        # Seed from the saved source settings so this reflects what a run launched
        # from the Overview page would search.
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

        # Apply merges into the saved source settings rather than replacing them,
        # so the caps configured in the Overview page's Sourcing modal (per-keyword,
        # max-per-domain, time budget, ...) survive an edit made here.
        _pending = {**_saved, "mode": mode}
        if selected and set(selected) != set(all_domains):
            _pending["domains"] = selected
        else:
            # Every sub-domain (or none) selected == no restriction: drop the key so
            # a later-added sub-domain is searched too, instead of being frozen out
            # by a stale list.
            _pending.pop("domains", None)
        _dirty = (_pending != _saved)

        if ui.right_slot().button("Apply", key="src_apply", type="primary",
                                  disabled=not selected or not _dirty,
                                  use_container_width=True,
                                  help="Save these sub-domains and mode as the "
                                       "Sourcing stage's defaults."):
            settings_store.save_stage("source", _pending)
            _scope = ("every sub-domain" if "domains" not in _pending
                      else f"{len(selected)} sub-domain(s)")
            st.success(f"Saved: Sourcing will search {_scope} in '{mode}' mode.")
            st.rerun()
        if not selected:
            st.caption("Select at least one sub-domain to apply.")
        elif not _dirty:
            _scope = ("every sub-domain" if "domains" not in _saved
                      else f"{len(_saved['domains'])} sub-domain(s)")
            st.caption(f"Saved: Sourcing searches {_scope} in "
                       f"'{_saved.get('mode', catalog.MODES[0])}' mode.")

    with ui.section("Keyword preview",
                    "The keywords a discovery run would use for the selection above."):
        kw_rows = [{"sub-domain": d, "keyword": k}
                   for d in selected for k in catalog.keywords_for(d, mode, cat)]
        with st.expander(f"Keywords that will run ({len(kw_rows)})",
                         expanded=not selected):
            if kw_rows:
                ui.table(kw_rows, height=300)
            else:
                st.caption("Select at least one sub-domain to see its keywords.")
        st.caption("Edit these keywords in the Sub-domains tab. The remaining run "
                   "caps live in the Overview page's Sourcing settings.")

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
            st.caption("No `Sources.csv` for this profile yet.")

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
                    "Act on the profile's `Sources.csv` instantly, no run needed. Deleted "
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

    def _lines(text: str) -> list[str]:
        return [ln.strip() for ln in text.splitlines() if ln.strip()]

    with ui.section("Edit a sub-domain",
                    "Change a sub-domain's name, schema code, or keywords. "
                    "Renaming can relabel its `Sources.csv` rows in the same edit "
                    "so they stay inside the taxonomy."):
        if not all_domains:
            st.caption("No sub-domains to edit. Add one below.")
        else:
            pick = st.selectbox("Sub-domain to edit", all_domains, key="ed_pick")
            spec = cat.get(pick) or {}
            # Widget keys carry the picked sub-domain so switching the selectbox
            # re-seeds every field from that sub-domain instead of holding the
            # previous one's text.
            new_name = st.text_input("Name", value=pick, key=f"ed_name_{pick}")
            new_code = st.text_input(
                "Enum code", value=catalog.code_for(pick, cat),
                key=f"ed_code_{pick}",
                help="The schema's `subdomain_name` enum value. Changing it "
                     "changes the label the schema stage files these records "
                     "under; blank re-derives it from the name.")
            ed1, ed2 = st.columns(2)
            new_ds = ed1.text_area("Dataset keywords (one per line)",
                                   value="\n".join(spec.get("datasets") or []),
                                   height=200, key=f"ed_ds_{pick}")
            new_tx = ed2.text_area("Text keywords (one per line)",
                                   value="\n".join(spec.get("text") or []),
                                   height=200, key=f"ed_tx_{pick}")
            new_vocab = st.text_area(
                "Classification vocabulary (one term per line)",
                value="\n".join(spec.get("vocab") or []), height=120,
                key=f"ed_vocab_{pick}",
                help="Short, distinctive terms used only to break ties when "
                     "discovery decides which sub-domain a hit belongs to. "
                     "Blank falls back to this sub-domain's keywords.")

            renaming = new_name.strip() and new_name.strip() != pick
            n_rows = cat_summary["by_domain"].get(pick, 0)
            relabel = True
            if renaming and n_rows:
                relabel = st.checkbox(
                    f"Also relabel this sub-domain's {n_rows} row(s) in "
                    "Sources.csv", value=True, key=f"ed_relabel_{pick}",
                    help="Leave this on unless you want the existing rows to keep "
                         "the old label. Rows left behind match no configured "
                         "sub-domain, so a selective run skips them.")
            if renaming and new_name.strip() in all_domains:
                st.error(f"'{new_name.strip()}' already exists. Pick another name.")

            _can_save = bool(new_name.strip()) and new_name.strip() not in (
                set(all_domains) - {pick})
            if ui.right_slot().button("Save changes", key=f"ed_save_{pick}",
                                      type="primary", disabled=not _can_save,
                                      use_container_width=True):
                try:
                    catalog.update_subdomain(
                        pick, name=new_name.strip(), datasets=_lines(new_ds),
                        text=_lines(new_tx), vocab=_lines(new_vocab),
                        code=new_code.strip())
                except (KeyError, ValueError) as ex:
                    st.error(str(ex))
                else:
                    msg = f"Saved '{new_name.strip()}' to sources/keywords.yaml"
                    if renaming and relabel:
                        moved = sheet.rename_subdomain(data.catalog_path(), pick,
                                                       new_name.strip())
                        msg += f" · relabelled {moved} catalog row(s)"
                    st.success(msg)
                    st.rerun()

    with ui.section("Add a sub-domain",
                    "Sub-domains and keywords persist to `sources/keywords.yaml`. "
                    "Adding one that already exists replaces it."):
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
                name.strip(), datasets=_lines(ds), text=_lines(tx),
                code=code.strip() or None)
            st.success(f"Saved '{name.strip()}' to sources/keywords.yaml")
            st.rerun()

    with ui.section("Remove a sub-domain",
                    "Removes it from the taxonomy. Its `Sources.csv` rows are left "
                    "alone — delete those separately in the Delete rows tab."):
        if all_domains:
            victim = st.selectbox("Sub-domain to remove", all_domains, key="rm_pick")
            _victim_rows = cat_summary["by_domain"].get(victim, 0)
            if _victim_rows:
                st.warning(f"{_victim_rows} catalog row(s) are filed under "
                           f"'{victim}'. They will stay in Sources.csv with a "
                           "label no configured sub-domain matches, so selective "
                           "runs will skip them. Rename it instead to keep them.")
            if st.button("Remove", key="rm_go", type="secondary"):
                catalog.remove_subdomain(victim)
                st.success(f"Removed '{victim}' from sources/keywords.yaml")
                st.rerun()
        else:
            st.caption("No sub-domains to remove.")

# ============================================================== Add source =====
with add_tab:
    with ui.section("Add a source by hand",
                    "Appends one row to `sources/Sources.csv`, identical in shape "
                    "to a discovered one, so the ingest stage picks it up on the "
                    "next run. Use this for a source discovery cannot find."):
        if not all_domains:
            st.info("No sub-domains configured yet. Add one in the Sub-domains tab "
                    "first, so this source has somewhere to be filed.")
        else:
            a1, a2 = st.columns(2)
            m_name = a1.text_input(
                "Name *", key="ms_name",
                help="Short label — the dataset's owner/org for HuggingFace and "
                     "GitHub sources (e.g. `darkknight25`).")
            m_dom = a2.selectbox("Sub-Domain *", all_domains, key="ms_dom")
            m_link = st.text_input(
                "Dataset Link *", key="ms_link",
                help="The source URL. It decides how ingestion fetches this "
                     "source (HuggingFace / Kaggle / GitHub / direct file / site).")
            m_desc = st.text_area("Description", key="ms_desc", height=80)

            b1, b2, b3 = st.columns(3)
            m_cat = b1.selectbox("Category", ["(infer from link)",
                                              *row_builder.CATEGORIES],
                                 key="ms_cat")
            m_fmt = b2.selectbox("Original Format", ["(infer from link)",
                                                     *row_builder.FORMATS],
                                 key="ms_fmt")
            m_lic = b3.text_input(
                "License", key="ms_lic",
                help="Free text (e.g. `MIT`, `Apache-2.0`, `CC0-1.0`). Ingestion "
                     "fetches a source only when its license is clearly "
                     "commercial-use; blank or unrecognised is turned away.")
            m_syn = st.checkbox(
                "Is Synthetic?", key="ms_syn",
                help="Model-generated content. Synthetic sources are cleaned but "
                     "excluded from the final dataset by the schema stage.")

            with st.expander("More fields (optional)"):
                st.caption("Left blank, these are filled in by the ingest and "
                           "clean stages as they measure the source.")
                e1, e2, e3 = st.columns(3)
                m_files = e1.text_input("File Count", key="ms_files")
                m_osize = e2.text_input("Original Size (MB)", key="ms_osize")
                m_lines = e3.text_input("Total Lines", key="ms_lines")
                f1, f2, f3 = st.columns(3)
                m_author = f1.text_input("Author", key="ms_author")
                m_updated = f2.text_input("Last Updated", key="ms_updated")
                m_tags = f3.text_input("Tags", key="ms_tags")
                m_note = st.text_input("Note", key="ms_note")

            _required = [m_name.strip(), m_dom, m_link.strip()]
            # Reject a link the catalog already has: normalize_url matches the same
            # source linked slightly differently, which is what discovery dedups on.
            _dupe = ""
            if m_link.strip():
                _existing = sheet.existing_links(data.catalog_path())
                if sheet.normalize_url(m_link) in _existing:
                    _dupe = ("This link is already in the catalog. Delete the "
                             "existing row first if you want to re-add it.")
                    st.warning(_dupe)

            if ui.right_slot().button("Add source", key="ms_add", type="primary",
                                      disabled=not all(_required) or bool(_dupe),
                                      use_container_width=True):
                try:
                    new_row = row_builder.build_manual_row(
                        name=m_name, subdomain=m_dom, link=m_link,
                        description=m_desc,
                        category="" if m_cat.startswith("(") else m_cat,
                        original_format="" if m_fmt.startswith("(") else m_fmt,
                        license=m_lic, is_synthetic=m_syn,
                        extra={"File Count": m_files,
                               "Original Size (MB)": m_osize,
                               "Total Lines": m_lines, "Author": m_author,
                               "Last Updated": m_updated, "Tags": m_tags,
                               "Note": m_note})
                except ValueError as ex:
                    st.error(str(ex))
                else:
                    sheet.append_rows(data.catalog_path(), [new_row])
                    st.success(f"Added '{new_row['Name']}' to sources/Sources.csv "
                               f"under {new_row['Sub-Domain']} · "
                               f"{new_row['Category']}"
                               + (f" / {new_row['Original Format']}"
                                  if new_row["Original Format"] else ""))
                    st.rerun()
            if not all(_required):
                st.caption("Name, Sub-Domain, and Dataset Link are required.")

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
            st.caption("No `Sources.csv` for this profile yet.")
        else:
            st.caption(f"{len(rows)} rows")
            ui.table(rows, height=520)
