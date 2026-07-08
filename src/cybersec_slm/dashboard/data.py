#!/usr/bin/env python3
"""Dashboard read layer — the ONLY code that touches the pipeline's artifacts.

Pure functions that read what the pipeline writes under the data root and return
plain Python (dict / list). No Streamlit import, so every function is unit-tested
headlessly. Paths resolve through ``core.data_root()`` on each call (a fresh read
of ``CYBERSEC_SLM_DATA_ROOT``), which is what makes this both testable against a
temporary root and "hosted-ready": point the root at a synced/mounted location and
the same functions serve a hosted deploy unchanged.

Every function tolerates missing artifacts (fresh checkout, or a run that hasn't
reached that stage yet) by returning an empty/None value instead of raising.
"""

from __future__ import annotations

import csv
import glob
import json
import os
import time

from .. import core

# A per-PID pipeline log touched within this window means a run is in progress.
# Heuristic (a long download can be quiet): the UI labels it "recent activity".
RUN_ACTIVE_WINDOW_S = 60.0
# Hard cap on how many dataset records a single query will scan/count, so a huge
# corpus can never make one page load unbounded. Surfaced to the UI as "capped".
DATASET_SCAN_CAP = 50_000

# Record fields the Dataset page filters on -> the facet key in the manifest.
FILTER_FIELDS = {
    "domain": ("domain_name", "domains"),
    "subdomain": ("subdomain_name", "subdomains"),
    "source": ("source", "sources"),
    "record_type": ("record_type", "record_types"),
    "lang": ("lang", "languages"),
}


# --------------------------------------------------------------- path helpers --
def _root() -> str:
    return core.data_root()


def _logs() -> str:
    return os.path.join(_root(), "logs")


def _final() -> str:
    return os.path.join(_root(), "data", "final")


def _clean() -> str:
    return os.path.join(_root(), "data", "clean")


def _eda_dir() -> str:
    return os.path.join(_logs(), "eda")


def _repo_root() -> str:
    # src/cybersec_slm/dashboard/data.py -> up 4 -> repo root (for the catalog).
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))))


def data_root() -> str:
    """The resolved data root the dashboard is reading from (shown in the UI)."""
    return _root()


# --------------------------------------------------------------- small readers -
def _read_json(path: str):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (ValueError, OSError):
        return None


def _read_csv(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f))
    except OSError:
        return []


# --------------------------------------------------------------- live monitor --
def _pipeline_logs() -> list[str]:
    return sorted(glob.glob(os.path.join(_logs(), "pipeline.*.log")),
                  key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0)


def run_status() -> dict:
    """Best-effort run state from the newest per-PID pipeline log's mtime."""
    logs = _pipeline_logs()
    if not logs:
        return {"state": "idle", "newest_log": None, "mtime": None, "age": None}
    newest = logs[-1]
    mtime = os.path.getmtime(newest)
    age = time.time() - mtime
    return {
        "state": "running" if age <= RUN_ACTIVE_WINDOW_S else "idle",
        "newest_log": newest,
        "mtime": mtime,
        "age": age,
    }


def _catalog_total() -> int | None:
    """Best-effort count of sources in the repo catalog (the run's denominator)."""
    path = os.path.join(_repo_root(), "sources", "Sources.csv")
    rows = _read_csv(path)
    return len(rows) if rows else None


def log_tail(n: int = 40) -> list[str]:
    """Last ``n`` lines of the newest per-PID pipeline log (empty if none)."""
    logs = _pipeline_logs()
    if not logs:
        return []
    try:
        with open(logs[-1], encoding="utf-8", errors="replace") as f:
            return [ln.rstrip("\n") for ln in f.readlines()[-n:]]
    except OSError:
        return []


def live_progress(tail: int = 40) -> dict:
    """Sources completed so far (from the resume ledger) + a log tail.

    ``completed`` counts ``logs/completed_sources.txt`` (each source is appended as
    it finishes, cleaned or license-skipped); ``total`` is the catalog size when
    it can be located, else None (the UI shows a bare count).
    """
    ledger = os.path.join(_logs(), "completed_sources.txt")
    completed = 0
    if os.path.exists(ledger):
        try:
            with open(ledger, encoding="utf-8") as f:
                completed = sum(1 for ln in f if ln.strip())
        except OSError:
            completed = 0
    return {"completed": completed, "total": _catalog_total(), "log_tail": log_tail(tail)}


# ------------------------------------------------------------------- EDA gate --
def latest_eda() -> dict | None:
    """Parsed ``logs/eda/latest.json`` (gate status, violations, metrics)."""
    return _read_json(os.path.join(_eda_dir(), "latest.json"))


def eda_history() -> list[dict]:
    """Every ``logs/eda/run-*.json``, oldest first (filenames sort chronologically)."""
    out = []
    for p in sorted(glob.glob(os.path.join(_eda_dir(), "run-*.json"))):
        rep = _read_json(p)
        if rep is not None:
            out.append(rep)
    return out


# --------------------------------------------------------------- stage reports -
def source_table() -> list[dict]:
    """Per-source summary rows from ``logs/final_table.csv`` (written at run end)."""
    return _read_csv(os.path.join(_logs(), "final_table.csv"))


def clean_report() -> dict:
    """``logs/clean_report.csv`` split into per-file rows + the TOTAL row."""
    rows = _read_csv(os.path.join(_logs(), "clean_report.csv"))
    total = next((r for r in rows if r.get("sub_domain") == "TOTAL"), None)
    files = [r for r in rows if r.get("sub_domain") != "TOTAL"]
    return {"total": total, "files": files}


def normalize_report() -> dict | None:
    """Parsed ``logs/normalize_report.json`` (counts, paused sources, categories)."""
    return _read_json(os.path.join(_logs(), "normalize_report.json"))


def manifest() -> dict | None:
    """Parsed ``data/final/manifest.json`` (the release datasheet)."""
    return _read_json(os.path.join(_final(), "manifest.json"))


# ---------------------------------------------------------------- dataset view -
def dataset_facets() -> dict:
    """Filter values + counts per field, sourced from the manifest when present.

    Returns ``{ui_field: {value: count}}`` for the FILTER_FIELDS, empty when no
    manifest exists yet (the UI then shows unfiltered browse only).
    """
    man = manifest() or {}
    facets: dict[str, dict] = {}
    for ui_field, (_rec_key, man_key) in FILTER_FIELDS.items():
        facets[ui_field] = dict(man.get(man_key) or {})
    return facets


def _matches(rec: dict, filters: dict, needle: str) -> bool:
    for ui_field, wanted in filters.items():
        if not wanted:
            continue
        rec_key = FILTER_FIELDS[ui_field][0]
        if rec.get(rec_key) != wanted:
            return False
    if needle:
        if needle not in (rec.get("text") or "").lower():
            return False
    return True


def dataset_page(filters: dict | None = None, search: str = "",
                 offset: int = 0, limit: int = 50) -> dict:
    """One page of ``data/final/dataset.jsonl`` after filter + substring search.

    Streams the file (never loads it whole). Returns
    ``{rows, match_count, capped, total_scanned}`` where ``match_count`` is the
    number of matches found within the first ``DATASET_SCAN_CAP`` records
    (``capped=True`` if that ceiling was reached, so the UI can say "first N+").
    """
    filters = filters or {}
    needle = (search or "").strip().lower()
    path = os.path.join(_final(), "dataset.jsonl")
    rows: list[dict] = []
    match_count = 0
    scanned = 0
    capped = False
    if not os.path.exists(path):
        return {"rows": rows, "match_count": 0, "capped": False, "total_scanned": 0}

    for rec in core.iter_jsonl(path):
        if rec.get(core.PARSE_ERROR):
            continue
        scanned += 1
        if scanned > DATASET_SCAN_CAP:
            capped = True
            break
        if not _matches(rec, filters, needle):
            continue
        if offset <= match_count < offset + limit:
            rows.append(rec)
        match_count += 1
    return {"rows": rows, "match_count": match_count, "capped": capped,
            "total_scanned": scanned}


def sidecar(kind: str, limit: int = 100) -> list[dict]:
    """Preview rows from a final-stage sidecar sink (bounded).

    ``kind`` is one of ``rejected`` / ``duplicates`` / ``dedup_scores``.
    """
    fname = {"rejected": "rejected.jsonl", "duplicates": "duplicates.jsonl",
             "dedup_scores": "dedup_scores.jsonl"}.get(kind)
    if not fname:
        return []
    path = os.path.join(_final(), fname)
    if not os.path.exists(path):
        return []
    out: list[dict] = []
    for rec in core.iter_jsonl(path):
        if rec.get(core.PARSE_ERROR):
            continue
        out.append(rec)
        if len(out) >= limit:
            break
    return out
