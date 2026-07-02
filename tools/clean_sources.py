#!/usr/bin/env python3
"""End-to-end driver: fetch + clean every source in the catalog CSV, lay the
cleaned output out per sub-domain, and mark Cleaned?=Yes back in the CSV.

For each row in ``sources/Sources.csv`` this:
  1. maps the row to a source descriptor (ingestion.sources._row_to_descriptor),
  2. fetches it, cleans it through the full cleaning pipeline, and writes the
     result to  data/clean/<Sub-Domain>/<source>/...  (folder per sub-domain),
  3. deletes the intermediate raw files,
  4. after the pool drains, runs one cross-source dedup pass, then sets
     Cleaned?=Yes for every row whose data/clean/ folder actually holds records
     (ground-truth marking — safe to re-run; it only ever adds Yes).

Drives fetch+clean across every sub-domain in the catalog.

Usage (run from anywhere; paths are pinned below):
    python tools/clean_sources.py                       # all sub-domains
    python tools/clean_sources.py --subdomain "Cloud Security"
    python tools/clean_sources.py --workers 6
    python tools/clean_sources.py dryrun                # preview, fetch nothing
    python tools/clean_sources.py mark                  # only re-mark from data/clean/
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import multiprocessing as mp
import os
import subprocess
import sys
import urllib.request
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed

PROJECT = r"c:/Users/vaibh/Documents/Main/Projects/cybersec-slm-data-pipeline"
CSV = os.path.join(PROJECT, "sources", "Sources.csv")
RESULTS_JSON = os.path.join(PROJECT, "logs", "clean_sources_results.json")

os.makedirs(os.path.join(PROJECT, "logs"), exist_ok=True)
os.chdir(PROJECT)
os.environ["CYBERSEC_SLM_DATA_ROOT"] = PROJECT

from cybersec_slm import core  # noqa: E402
from cybersec_slm.cleaning import pipeline  # noqa: E402
from cybersec_slm.ingestion import sources, worker  # noqa: E402

# --------------------------------------------------------------- dependencies --
# import-name -> (pip package, what it does). We install ONLY the modules that
# are actually missing — never the whole extra — so an already-working package
# (e.g. fasttext) is never needlessly rebuilt.
_REQUIRED_MODULES = {
    "ftfy": ("ftfy", "encoding repair (sanitize)"),
    "dateutil": ("python-dateutil", "date parsing (sanitize)"),
    "datasketch": ("datasketch", "near-dup MinHash/LSH (dedup)"),
    "langdetect": ("langdetect", "language id fallback (langfilter)"),
    "deep_translator": ("deep-translator", "translate non-English -> English"),
    # best-effort below: build-fragile on Windows / large; pipeline has fallbacks
    "presidio_analyzer": ("presidio-analyzer", "PII detection (pii)"),
    "presidio_anonymizer": ("presidio-anonymizer", "PII redaction (pii)"),
    "fasttext": ("fasttext-predict", "language id (langfilter)"),
}
# Modules whose absence only downgrades quality — install best-effort, never abort.
_OPTIONAL_MODULES = {"presidio_analyzer", "presidio_anonymizer", "fasttext"}
_SPACY_MODEL = "en_core_web_lg"          # used by presidio for full PII
_FASTTEXT_MODEL = os.path.join(PROJECT, "src", "cybersec_slm", "cleaning", "lid.176.ftz")
_FASTTEXT_URL = ("https://dl.fbaipublicfiles.com/fasttext/supervised-models/"
                 "lid.176.ftz")
_KAGGLE_TOKEN = os.path.join(os.path.expanduser("~"), ".kaggle", "access_token")


def _have(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def _pip_install(*args: str) -> None:
    subprocess.check_call([sys.executable, "-m", "pip", "install", *args])


def ensure_deps() -> None:
    """Install everything the cleaning pipeline needs BEFORE any source runs.

    Critical packages (incl. the translator) are a hard requirement — the run
    aborts if they can't be installed, so non-English text is never silently
    dropped. Presidio and the language models are best-effort: missing them only
    downgrades quality (regex PII / langdetect), so they warn instead of abort.
    Idempotent — already-present packages/models are skipped.
    """
    print("[deps] checking cleaning dependencies...", flush=True)
    missing = [m for m in _REQUIRED_MODULES if not _have(m)]
    if not missing:
        print("[deps] all cleaning packages present", flush=True)
    else:
        crit = [m for m in missing if m not in _OPTIONAL_MODULES]
        opt = [m for m in missing if m in _OPTIONAL_MODULES]
        print("[deps] missing packages:", flush=True)
        for m in missing:
            tag = "optional" if m in _OPTIONAL_MODULES else "REQUIRED"
            print(f"         - {m} ({tag}): {_REQUIRED_MODULES[m][1]}", flush=True)

        # Required: must succeed or we abort (so non-English is never dropped).
        if crit:
            pkgs = [_REQUIRED_MODULES[m][0] for m in crit]
            print(f"[deps] installing required: {', '.join(pkgs)}", flush=True)
            try:
                _pip_install(*pkgs)
            except subprocess.CalledProcessError as ex:
                raise SystemExit(f"[deps] FAILED to install required packages: {ex}\n"
                                 "Fix the error above and re-run.") from ex
        # Optional: install one at a time so a build failure (e.g. fasttext needs
        # a C++ compiler on Windows) only downgrades that one stage.
        for m in opt:
            pkg = _REQUIRED_MODULES[m][0]
            print(f"[deps] installing optional: {pkg}", flush=True)
            try:
                _pip_install(pkg)
            except subprocess.CalledProcessError:
                print(f"[deps] WARNING: '{pkg}' install failed (needs a build "
                      f"toolchain?); continuing with the pipeline's fallback.",
                      flush=True)
        importlib.invalidate_caches()

    # spaCy model for presidio (PII falls back to regex without it) — best-effort
    if _have("presidio_analyzer") and not _have(_SPACY_MODEL):
        print(f"[deps] downloading spaCy model {_SPACY_MODEL} (~600MB, one-time)...",
              flush=True)
        try:
            subprocess.check_call([sys.executable, "-m", "spacy", "download", _SPACY_MODEL])
            importlib.invalidate_caches()
        except subprocess.CalledProcessError:
            print("[deps] WARNING: spaCy model download failed; PII uses regex.",
                  flush=True)

    # fastText language-id model (kept out of git) — best-effort (langdetect covers it)
    if not os.path.exists(_FASTTEXT_MODEL):
        print("[deps] downloading fastText lid.176 model...", flush=True)
        os.makedirs(os.path.dirname(_FASTTEXT_MODEL), exist_ok=True)
        try:
            urllib.request.urlretrieve(_FASTTEXT_URL, _FASTTEXT_MODEL)
        except Exception:
            print("[deps] WARNING: fastText model download failed; language id uses "
                  "langdetect/heuristic.", flush=True)

    # Kaggle credentials (kaggle-kind sources fail to fetch without them)
    if not os.path.exists(_KAGGLE_TOKEN) and not os.environ.get("KAGGLE_API_TOKEN"):
        print("[deps] WARNING: no Kaggle token (~/.kaggle/access_token or "
              "KAGGLE_API_TOKEN); kaggle sources will be skipped/failed.", flush=True)

    _report_backends()


def _report_backends() -> None:
    """Print the backend each cleaning stage actually resolved to."""
    from cybersec_slm.cleaning.dedup import Deduper
    from cybersec_slm.cleaning.langfilter import LangFilter
    from cybersec_slm.cleaning.pii import Redactor
    from cybersec_slm.cleaning.translate import Translator
    print(f"[deps] backends -> dedup:{Deduper().backend} pii:{Redactor().engine} "
          f"lang:{LangFilter().backend} translate:{Translator().backend}", flush=True)
    if Translator().backend == "none":
        raise SystemExit("[deps] translator backend is still 'none' after install — "
                         "aborting so non-English text is not silently dropped.")


# ------------------------------------------------------------------- catalog --
def load_rows(subdomain: str | None):
    """Return [{row_idx, name, url, sub_domain, descriptor|None, already}].

    ``row_idx`` is the 0-based DataFrame index of the row in Sources.csv — the
    handle :func:`mark_csv` uses to write Cleaned?/sizes back to that exact row.
    """
    import pandas as pd

    df = pd.read_csv(CSV, dtype=str, keep_default_na=False, encoding="utf-8")
    df = sources._norm_headers(df)                # headers -> snake_case
    out = []
    for idx, rd in enumerate(df.to_dict("records")):    # idx == DataFrame row index
        sub = str(rd.get("sub_domain", "")).strip()
        if subdomain is not None and sub != subdomain:
            continue
        url = sources._val(rd, "url", "dataset_link", "link", "source_url", default="")
        name = sources._val(rd, "name", "source_name", "title", default=url)
        desc = sources._row_to_descriptor(rd)
        if desc is not None:
            desc = dict(desc)
            desc["_row_idx"] = idx
            desc["_xname"] = name
            desc["_xurl"] = url
        cleaned_flag = str(rd.get("cleaned?", "")).strip().lower()
        out.append({"row_idx": idx, "name": name, "url": url,
                    "sub_domain": sub, "descriptor": desc,
                    "already": cleaned_flag in ("yes", "y", "true", "1")})
    return out


def clean_dir_for(descriptor: dict) -> str:
    """The data/clean/ folder a descriptor's output lands in (mirrors worker).

    Pure path computation — mirrors fetch._folder's naming (base == owner when a
    single source uses that owner) without creating any directories.
    """
    kind = descriptor["kind"]
    domain = descriptor["domain"]
    if kind in ("hf", "kaggle", "url", "github"):
        ref = descriptor["ref"]
        name = ref.split("/")[-1]
        owner = ref.split("/")[0] if "/" in ref and kind in ("hf", "kaggle") else name
        sub = owner
    else:
        sub = descriptor["slug"]
    return os.path.join(core.CLEAN_DATA, domain, sub)


def clean_stats(d: str) -> tuple[float, int]:
    """(total .jsonl size in MB, total non-empty lines) under a data/clean/ folder.

    A row counts as cleaned when this returns lines > 0; the size/line figures are
    written straight into the CSV's Cleaned Size (MB) / Cleaned Lines columns.
    """
    total_bytes = lines = 0
    if os.path.isdir(d):
        for root, _dirs, files in os.walk(d):
            for fn in files:
                if not fn.endswith(".jsonl"):
                    continue
                p = os.path.join(root, fn)
                try:
                    total_bytes += os.path.getsize(p)
                    with open(p, encoding="utf-8", errors="replace") as f:
                        lines += sum(1 for line in f if line.strip())
                except OSError:
                    pass
    return round(total_bytes / (1024 * 1024), 3), lines


def _csv_col(columns, want: str) -> str | None:
    """Find the real column name whose lowercased form equals ``want``."""
    for c in columns:
        if str(c).strip().lower() == want:
            return c
    return None


def mark_csv(stats: dict[int, tuple[float, int]], mappable: set[int]) -> None:
    """Write data/clean ground truth back into Sources.csv for every mappable row.

    Rows whose data/clean/ folder holds records (in `stats`, keyed by row_idx) get
    Cleaned?=Yes plus their Cleaned Size (MB) and Cleaned Lines. Mappable rows that
    own no records — a source that produced nothing, or one merged away by a
    same-owner folder collision — are cleared, so the Cleaned Lines column always
    sums to the real corpus size instead of retaining stale numbers from an earlier
    run. Non-mappable rows are never touched.
    """
    if not mappable:
        print("[mark] nothing to mark (no mappable rows)", flush=True)
        return
    import pandas as pd

    df = pd.read_csv(CSV, dtype=str, keep_default_na=False, encoding="utf-8")
    col_flag = _csv_col(df.columns, "cleaned?")
    col_size = _csv_col(df.columns, "cleaned size (mb)")
    col_lines = _csv_col(df.columns, "cleaned lines")
    if col_flag is None:
        print("[mark] WARNING: no 'Cleaned?' column in Sources.csv; skipping", flush=True)
        return
    marked = cleared = 0
    for idx in range(len(df)):
        was_yes = str(df.at[idx, col_flag]).strip().lower() in ("yes", "y")
        had_lines = bool(col_lines is not None and str(df.at[idx, col_lines]).strip())
        if idx in stats:
            size_mb, lines = stats[idx]
            df.at[idx, col_flag] = "Yes"
            if not was_yes:
                marked += 1
            if col_size is not None:
                df.at[idx, col_size] = str(size_mb)
            if col_lines is not None:
                df.at[idx, col_lines] = str(lines)
        elif idx in mappable:
            # Mappable but owns no cleaned records -> clear the cells (ground truth).
            df.at[idx, col_flag] = ""
            if col_size is not None:
                df.at[idx, col_size] = ""
            if col_lines is not None:
                df.at[idx, col_lines] = ""
            if was_yes or had_lines:
                cleared += 1
    try:
        tmp = CSV + ".tmp"
        df.to_csv(tmp, index=False, encoding="utf-8")
        os.replace(tmp, CSV)                      # atomic; never a half-written catalog
        print(f"[mark] {len(stats)} rows Cleaned?=Yes ({marked} newly), "
              f"{cleared} stale rows cleared, in {os.path.basename(CSV)}", flush=True)
    except OSError:
        alt = CSV.replace(".csv", ".cleaned.csv")
        df.to_csv(alt, index=False, encoding="utf-8")
        print(f"[mark] {CSV} is locked (open in Excel?); wrote {alt} instead", flush=True)


def collect_stats(rows) -> dict[int, tuple[float, int]]:
    """Map each mappable row's Excel-row number -> (cleaned MB, lines), counting
    every data/clean/ folder exactly once.

    Several rows can resolve to the *same* data/clean/<Sub-Domain>/<owner> folder:
    two Hugging Face / Kaggle datasets published under one owner both clean into
    data/clean/<domain>/<owner> (see clean_dir_for, which mirrors the ingestion
    worker's owner-based naming). Crediting that shared folder to each colliding
    row would count its records once per row and inflate the corpus total — the
    bug that pushed the catalog total above the real ~538k. So a folder is
    credited to a single row (the lowest row_idx); the rest are reported and
    left uncredited, because the collision merged their output into one folder.
    """
    by_folder: dict[str, list[dict]] = {}
    for r in rows:
        if not r["descriptor"]:
            continue
        folder = os.path.normpath(clean_dir_for(r["descriptor"]))
        by_folder.setdefault(folder, []).append(r)

    stats: dict[int, tuple[float, int]] = {}
    for folder, group in by_folder.items():
        size_mb, lines = clean_stats(folder)
        if lines <= 0:
            continue
        group.sort(key=lambda r: r["row_idx"])
        winner = group[0]
        stats[winner["row_idx"]] = (size_mb, lines)
        if len(group) > 1:
            losers = [g["row_idx"] for g in group[1:]]
            rel = os.path.relpath(folder, core.CLEAN_DATA)
            print(f"[mark] collision: rows {[g['row_idx'] for g in group]} share "
                  f"{rel} ({lines:,} lines); credited row {winner['row_idx']}, "
                  f"left {losers} uncredited (same-owner folder collision)", flush=True)
    return stats


# ------------------------------------------------------------------ actions ---
def dryrun(subdomain: str | None):
    rows = load_rows(subdomain)
    print(f"sub-domain '{subdomain}'" if subdomain else "all sub-domains")
    print("rows considered :", len(rows))
    print("mappable        :", sum(1 for r in rows if r["descriptor"]))
    print("no-descriptor   :", sum(1 for r in rows if r["descriptor"] is None))
    print("already Yes     :", sum(1 for r in rows if r["already"]))
    print("by sub-domain   :",
          dict(Counter(r["sub_domain"] for r in rows if r["descriptor"])))
    print("by kind         :",
          dict(Counter(r["descriptor"]["kind"] for r in rows if r["descriptor"])))


def mark_only(subdomain: str | None):
    """No fetching — just mark rows whose data/clean/ folder already has records."""
    rows = load_rows(subdomain)
    stats = collect_stats(rows)
    mappable = {r["row_idx"] for r in rows if r["descriptor"]}
    print(f"[mark] {len(stats)} rows have records under data/clean/", flush=True)
    mark_csv(stats, mappable)


def run(subdomain: str | None, workers: int | None,
        skip_deps: bool = False):
    if not skip_deps:
        ensure_deps()
    rows = load_rows(subdomain)
    scope = subdomain or "all sub-domains"
    print(f"[clean] {scope}: {len(rows)} rows", flush=True)

    todo = [r for r in rows if r["descriptor"] is not None and not r["already"]]
    skipped = [r for r in rows if r["descriptor"] is None]
    already = [r for r in rows if r["already"] and r["descriptor"] is not None]
    print(f"[clean] to process: {len(todo)}  already-Yes: {len(already)}  "
          f"no-descriptor: {len(skipped)}", flush=True)
    if not todo:
        print("[clean] nothing to do; running mark pass only", flush=True)

    descriptors = [r["descriptor"] for r in todo]
    workers = workers or min(os.cpu_count() or 4, 6)
    results: dict[int, dict] = {}
    done = 0
    ctx = mp.get_context("spawn")
    if descriptors:
        with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as ex:
            futs = {ex.submit(worker.process_source, d, data_root=PROJECT,
                              clean_data_dir=core.CLEAN_DATA, keep_raw=False): d
                    for d in descriptors}
            for fut in as_completed(futs):
                d = futs[fut]
                er = d["_row_idx"]
                label = d.get("_xname") or d.get("ref") or d.get("slug")
                try:
                    meta = fut.result()
                    rep = meta.get("clean_report_rows", [])
                    out_recs = sum(int(x.get("out", 0)) for x in rep)
                    in_recs = sum(int(x.get("in", 0)) for x in rep)
                    status, err = meta.get("status"), meta.get("error")
                except Exception as ex2:
                    status, out_recs, in_recs, err = "failed", 0, 0, \
                        f"{type(ex2).__name__}: {ex2}"
                results[er] = {"row_idx": er, "name": label, "url": d.get("_xurl"),
                               "sub_domain": d.get("domain"), "kind": d.get("kind"),
                               "status": status, "in": in_recs, "out": out_recs,
                               "error": err}
                done += 1
                print(f"[{done}/{len(todo)}] row{er} {str(d.get('kind')):8} "
                      f"{status:6} in={in_recs} out={out_recs}  {str(label)[:55]}",
                      flush=True)
                with open(RESULTS_JSON, "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2)

    # one cross-source dedup pass over everything written this run
    try:
        pipeline.final_global_dedup(core.CLEAN_DATA)
    except Exception as ex2:
        print(f"[clean] final dedup skipped: {ex2}", flush=True)

    for r in skipped:
        results[r["row_idx"]] = {"row_idx": r["row_idx"], "name": r["name"],
                                 "url": r["url"], "sub_domain": r["sub_domain"],
                                 "kind": None, "status": "skipped_no_descriptor",
                                 "in": 0, "out": 0,
                                 "error": "could not map row to a source"}
    with open(RESULTS_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # ground-truth marking: every row whose data/clean/ folder holds records is
    # written back with Cleaned?=Yes + its Cleaned Size (MB) and Cleaned Lines.
    cleaned_stats = collect_stats(rows)
    mappable = {r["row_idx"] for r in rows if r["descriptor"]}
    mark_csv(cleaned_stats, mappable)

    ok = [v for v in results.values() if v["status"] == "ok" and v["out"] > 0]
    zero = [v for v in results.values() if v["status"] == "ok" and v["out"] == 0]
    fail = [v for v in results.values() if v["status"] not in ("ok",)]
    print("\n===== SUMMARY =====", flush=True)
    print(f"cleaned (out>0)      : {len(ok)}", flush=True)
    print(f"ok but 0 records     : {len(zero)}", flush=True)
    print(f"failed/skipped       : {len(fail)}", flush=True)
    print(f"already Yes (skipped): {len(already)}", flush=True)
    print(f"rows marked Cleaned? : {len(cleaned_stats)}", flush=True)
    print(f"results -> {RESULTS_JSON}", flush=True)


def main():
    p = argparse.ArgumentParser(description="Fetch+clean Sources.csv sources, mark Cleaned?=Yes")
    p.add_argument("action", nargs="?", default="run", choices=["run", "dryrun", "mark"])
    p.add_argument("--subdomain", default=None, help="limit to one Sub-Domain (default: all)")
    p.add_argument("--workers", type=int, default=None, help="process pool size")
    p.add_argument("--skip-deps", action="store_true",
                   help="skip the pre-run dependency install/check")
    p.add_argument("--deps-only", action="store_true",
                   help="install/verify all dependencies, then exit")
    args = p.parse_args()

    if args.deps_only:
        ensure_deps()
    elif args.action == "dryrun":
        dryrun(args.subdomain)
    elif args.action == "mark":
        mark_only(args.subdomain)
    else:
        run(args.subdomain, args.workers, skip_deps=args.skip_deps)


if __name__ == "__main__":
    main()
