#!/usr/bin/env python3
"""Clean (stage 3): inspect the cleaned corpus under data/clean/.

Read-only. Run this stage and watch the log from the Overview page; every value
here comes from :mod:`cybersec_slm.dashboard.data`.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import cached, charts, data, ui

ui.inject_css()
ui.page_header("clean", data.stage_states())
st.caption("Cleaned and cross-source deduplicated records under `data/clean/`. "
           "Run this stage from the Overview page.")

# ------------------------------------------------------------------ stats ------
funnel = cached.data_funnel(data.data_root())
cleaned = funnel["cleaned"]
with ui.section("Cleaned"):
    c = st.columns(3)
    c[0].metric("Sources", charts.fmt_int(cleaned["sources"]))
    c[1].metric("Records", charts.fmt_int(cleaned["lines"]))
    c[2].metric("Size", charts.fmt_size(cleaned["size_mb"]))

# ------------------------------------------------------- what cleaning did -----
stats = data.clean_stats()
with ui.section("What cleaning did",
                "Every counter the cleaning pass records, in the order the stages "
                "run: map text -> sanitize -> anomaly check -> dedup -> PII "
                "redaction -> language filter."):
    if not stats["has_report"]:
        st.caption("No `logs/clean_report.csv` yet. Run the clean stage to see "
                   "what each mechanism removed, redacted, or repaired.")
    else:
        counts = stats["counts"]
        ui.stat_grid([
            ("Records in", charts.fmt_int(counts["in"])),
            ("Records out", charts.fmt_int(counts["out"])),
            ("Kept", f"{stats['kept_pct']:.1f}%"),
            ("PII redacted", charts.fmt_int(counts["pii_redacted"])),
        ], cols=4)
        st.caption(f"Across {charts.fmt_int(stats['files'])} file(s). "
                   "PII redacted counts *records* with at least one identifier "
                   "replaced by a typed placeholder, not the number of identifiers.")

        # Every remaining counter as a labelled table, so each mechanism's meaning
        # is on the row rather than hidden behind a column name from the CSV.
        detail = [
            {"stage": label, "records": counts[col],
             "% of input": (f"{100 * counts[col] / counts['in']:.2f}%"
                            if counts["in"] else "-"),
             "what it means": help_txt}
            for col, label, help_txt in data.CLEAN_COUNTERS
            if col not in ("in", "out")
        ]
        ui.table(detail, height=380)

# ----------------------------------------------------- per-source clean table --
with ui.section("Per-source cleaning stats",
                "What the cleaning pass did to each source: how many records went "
                "in and out, and how many each mechanism removed or changed."):
    ct = data.clean_table()
    if not ct:
        st.caption("No clean report yet. Run the clean stage above.")
    else:
        st.caption(f"{len(ct)} sources in `logs/clean_report.csv`.")
        ui.table([{"source": r["source"], "sub-domain": r["sub-domain"],
                   "in": r["in"], "out": r["out"], "kept %": r["kept_pct"],
                   "pii": r["pii_redacted"], "exact dups": r["exact_dups"],
                   "near dups": r["near_dups"], "struct": r["struct_dropped"],
                   "flagged": r["behavioral_flagged"],
                   "no prose": r["excluded_no_text"],
                   "translated": r["translated"],
                   "non-en dropped": r["non_en_dropped"],
                   "sanitized": r["sanitized"]} for r in ct], height=420)

# ----------------------------------------------------------- cleaned table -----
with ui.section("Cleaned sources", "What is physically under `data/clean/` now, "
                                   "measured on disk."):
    ct_disk = cached.cleaned_table(data.data_root())
    if ct_disk:
        st.caption(f"{len(ct_disk)} sources under `data/clean/`.")
        ui.table(ct_disk, height=340)
    else:
        st.caption("Nothing cleaned yet. Run the clean stage above.")

# ---------------------------------------------------------- where data went ----
with ui.section("Where did my data go?"):
    lb = data.loss_breakdown()
    active = [s for s in lb["stages"] if s["dropped"] > 0]
    if not active and not lb["per_source"]:
        st.caption("No clean report yet. Run the clean stage to see the drop "
                   "breakdown.")
    else:
        lc = st.columns(3)
        lc[0].metric("Raw records in", charts.fmt_int(lb["raw_in"]))
        lc[1].metric("After cleaning", charts.fmt_int(lb["clean_out"]))
        lc[2].metric("In final dataset", charts.fmt_int(lb["final_written"]))

        st.markdown("**Dropped by mechanism** (biggest first)")
        ranked = sorted(active, key=lambda s: s["dropped"], reverse=True)
        ui.table(
            [{"stage": s["stage"], "mechanism": s["mechanism"],
              "records dropped": s["dropped"], "kind": s["kind"]} for s in ranked],
            height=260)

        st.markdown("**Per-source losses** (biggest first)")
        rows = lb["per_source"]
        if rows:
            ui.table(
                [{"source": r["source"], "sub-domain": r["sub_domain"],
                  "in": r["in"], "out": r["out"], "kept %": r["kept_pct"],
                  "lost": r["lost"], "top reason": r["top_drop_reason"]}
                 for r in rows[:200]], height=300)
        else:
            st.caption("No per-source clean rows yet.")
