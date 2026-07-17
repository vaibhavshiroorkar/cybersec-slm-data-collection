#!/usr/bin/env python3
"""Dashboard read layer - the ONLY code that touches the pipeline's artifacts.

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
import re
import sqlite3
import time

from .. import core, stages

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
    # Skip empty stub logs: any cybersec_slm process (a test, or the dashboard
    # itself) creates a pipeline.<pid>.log on import; only a real run writes to it.
    # Filtering empties keeps those stubs from reading as "recent activity".
    #
    # Also skip the dashboard's OWN process log: this process logs on every rerun
    # (the live funnel loads the source catalog each tick), so its log is not empty
    # and is continuously the newest by mtime - which would make phase/status read
    # the dashboard's own chatter instead of the running pipeline's log and report
    # "Starting" forever. The pipeline runs as a separate detached process, so its
    # log has a different pid and is never excluded here.
    own = f"pipeline.{os.getpid()}.log"
    paths = [p for p in glob.glob(os.path.join(_logs(), "pipeline.*.log"))
             if os.path.basename(p) != own
             and os.path.exists(p) and os.path.getsize(p) > 0]
    return sorted(paths, key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0)


# Pointer file the full-run orchestrator writes with its real log path (see
# cybersec_slm.dashboard.run_all.RUN_LOG_POINTER).
_RUN_LOG_POINTER = "active_run_log.txt"


def _current_run_log() -> str | None:
    """The active (or most-recent) full run's log file.

    The orchestrator records its real log path in the pointer file at startup, so
    the dashboard follows the run's log directly. This is necessary because the
    run's pid can differ from the launched pid (Windows launcher shim) and the
    parallel clean workers spawn their own per-pid logs that would otherwise win
    newest-by-mtime and leave phase detection stuck on "Starting". Falls back to
    the newest non-own log when the pointer is absent (a run launched another way,
    or one predating the pointer).
    """
    ptr = os.path.join(_logs(), _RUN_LOG_POINTER)
    try:
        with open(ptr, encoding="utf-8") as f:
            p = f.read().strip()
        if p and os.path.exists(p) and os.path.getsize(p) > 0:
            return p
    except OSError:
        pass
    logs = _pipeline_logs()
    return logs[-1] if logs else None


_GATE_FAILED_LABEL = "EDA gate failed - needs more / rebalanced data"


def _strip_log_prefix(line: str) -> str:
    """Drop the loguru ``<ts> | LEVEL | module:func:line - `` prefix, keep the msg."""
    return re.sub(r"^.*?:\d+ - ", "", line).strip() or line.strip()


def run_phase(lookback: int = 500) -> dict:
    """Best-effort current (or last-reached) pipeline stage from the newest log.

    Reads the canonical five-stage model from :mod:`cybersec_slm.stages`. Returns
    ``{"phase", "label", "detail", "index", "total", "terminal"}``. ``phase`` is a
    stage key (``source``/``ingest``/``clean``/``eda``/``schema``) plus
    ``gate_failed`` (the EDA gate stopped the run and looped back), ``starting`` and
    ``unknown``. When idle this reflects the *last* run's furthest-reached stage /
    outcome, so the UI shows "EDA gate failed" or the final stage rather than a bare
    "idle".
    """
    total = len(stages.STAGES)
    # The RUN's log, not merely the newest one: during a parallel clean every
    # worker writes its own pipeline.<pid>.log (and any cybersec_slm process, a
    # test included, drops a stub in logs/), so newest-by-mtime reads a log with
    # no stage markers and reports "Starting..." for the whole stage.
    newest = _current_run_log()
    lines: list[str] = []
    if newest and os.path.exists(newest):
        try:
            with open(newest, encoding="utf-8", errors="replace") as f:
                lines = [ln.rstrip("\n") for ln in f.readlines()[-lookback:]]
        except OSError:
            lines = []
    if not lines:
        return {"phase": "unknown", "label": "No pipeline activity yet", "detail": "",
                "index": 0, "total": total, "terminal": False}

    # Terminal off-ramp: the gate can fail and loop back to ingestion. It only
    # counts if it is the LAST gate verdict (a later stage marker supersedes it).
    gate_failed_at = next((i for i, ln in enumerate(lines)
                           if "EDA sufficiency gate FAILED" in ln), None)

    key = stages.phase_from_log(lines)
    if key == "starting":
        return {"phase": "starting", "label": "Starting...", "detail": "",
                "index": 0, "total": total, "terminal": False}
    if key == "unknown":
        return {"phase": "unknown", "label": "No pipeline activity yet", "detail": "",
                "index": 0, "total": total, "terminal": False}

    keys = stages.stage_keys()
    idx = keys.index(key)                 # 0-based position in the spine
    stage = stages.get_stage(key)
    eda_idx = keys.index("eda")

    # A gate failure that came after the furthest stage marker is the real state.
    if gate_failed_at is not None and idx <= eda_idx:
        last_marker_at = max((i for i, ln in enumerate(lines)
                              if any(m in ln for m in stage.markers)), default=-1)
        if gate_failed_at >= last_marker_at:
            return {"phase": "gate_failed", "label": _GATE_FAILED_LABEL,
                    "detail": _strip_log_prefix(lines[gate_failed_at]),
                    "index": eda_idx + 1, "total": total, "terminal": True}

    detail = ""
    for ln in reversed(lines):
        if any(m in ln for m in stage.markers):
            detail = _strip_log_prefix(ln)
            break
    return {"phase": key, "label": stage.label, "detail": detail,
            "index": idx + 1, "total": total, "terminal": key == "schema"}


def _artifact_done(key: str) -> bool:
    """Whether a stage has produced its output artifact (survives raw deletion)."""
    if key == "source":
        return bool(_catalog_total())
    if key == "ingest":
        return _ingest_ledger_stats()["sources"] > 0 or _completed_count() > 0
    if key == "clean":
        return clean_report().get("total") is not None
    if key == "eda":
        return latest_eda() is not None
    if key == "schema":
        return manifest() is not None
    return False


def stage_states() -> dict:
    """Per-stage status for the Overview strip: ``{key: {"state", "detail"}}``.

    ``state`` is ``done`` / ``running`` / ``failed`` / ``pending``. Derived from the
    live (or last-reached) phase plus each stage's output artifact, so a completed
    run shows every stage ``done`` even after ``data/raw/`` was deleted. A gate
    failure marks ``eda`` as ``failed``.
    """
    ph = run_phase()
    running = run_status()["state"] == "running"
    pk = ph.get("phase")
    keys = stages.stage_keys()
    out: dict[str, dict] = {}
    if pk == "gate_failed":
        eda_i = keys.index("eda")
        for i, k in enumerate(keys):
            if k == "eda":
                out[k] = {"state": "failed", "detail": ph.get("detail", "")}
            else:
                out[k] = {"state": "done" if i < eda_i else "pending", "detail": ""}
        return out
    cur = keys.index(pk) if pk in keys else -1
    for i, k in enumerate(keys):
        if running and i == cur:
            state = "running"
        elif i < cur or _artifact_done(k):
            state = "done"
        else:
            state = "pending"
        out[k] = {"state": state, "detail": ph.get("detail", "") if i == cur else ""}
    return out


def run_status() -> dict:
    """Run state: authoritative from the dashboard control file when present.

    A run launched from the dashboard writes a control file, so its state is exact
    (PID liveness) and does not linger on stale log mtimes after it ends. A run
    started from the CLI has no control file, so fall back to the newest non-empty
    pipeline log's mtime (a long, quiet download can briefly read as idle).

    ``phase`` (parsed from the log) rides along so the UI can show which stage the
    run is in (or, when idle, the last run's outcome) instead of only on/off.
    """
    from . import control
    cstat = control.status()
    logs = _pipeline_logs()
    newest = logs[-1] if logs else None
    mtime = os.path.getmtime(newest) if newest and os.path.exists(newest) else None
    age = (time.time() - mtime) if mtime is not None else None

    if cstat.get("pid") is not None:               # dashboard-tracked run: exact
        state = "running" if cstat["running"] else "idle"
    elif age is not None and age <= RUN_ACTIVE_WINDOW_S:
        state = "running"                          # CLI run: log-mtime heuristic
    else:
        state = "idle"
    return {"state": state, "newest_log": newest, "mtime": mtime, "age": age,
            "pid": cstat.get("pid"), "phase": run_phase()}


def _catalog_total() -> int | None:
    """Best-effort count of sources in the repo catalog (the run's denominator)."""
    rows = _read_csv(_catalog_path())
    return len(rows) if rows else None


def _catalog_path() -> str:
    """The active profile's Sources.csv — follows a profile switch."""
    from ..sourcing import profiles
    return profiles.catalog_path()


def catalog_path() -> str:
    """Path to the source catalog CSV the dashboard reads and edits."""
    return _catalog_path()


def catalog_rows() -> list[dict]:
    """Every row of the active profile's source catalog, as read."""
    return _read_csv(_catalog_path())


def catalog_summary() -> dict:
    """Source catalog overview: total rows + per-Sub-Domain counts.

    Read straight from the active profile's ``Sources.csv`` so the landing page
    has a meaningful distribution to show even before any run has produced a
    manifest.
    Returns ``{"total": int, "by_domain": {name: count}}`` (empty when absent).
    """
    rows = catalog_rows()
    by_domain: dict[str, int] = {}
    for r in rows:
        dom = (r.get("Sub-Domain") or "").strip() or "Uncategorized"
        by_domain[dom] = by_domain.get(dom, 0) + 1
    return {"total": len(rows), "by_domain": by_domain}


def catalog_subdomains() -> list[str]:
    """Sorted Sub-Domains present in the source catalog (for selective ingest)."""
    return sorted(catalog_summary()["by_domain"].keys())


def _blacklist_path() -> str:
    """The active profile's Blacklist.csv — follows a profile switch."""
    from ..sourcing import profiles
    return profiles.blacklist_path()


def blacklist_rows() -> list[dict]:
    """Every row of the license blacklist (the active profile's ``Blacklist.csv``), as read."""
    return _read_csv(_blacklist_path())


def blacklist_summary() -> dict:
    """Blacklist overview: total rows + per-reason counts (empty when absent)."""
    rows = blacklist_rows()
    by_reason: dict[str, int] = {}
    for r in rows:
        reason = (r.get("Blacklist Reason") or "").strip() or "unspecified"
        by_reason[reason] = by_reason.get(reason, 0) + 1
    return {"total": len(rows), "by_reason": by_reason}


def license_coverage() -> dict:
    """Catalog license coverage using the gate verdict.

    Returns ``{"total", "filled", "unknown", "red"}`` where ``unknown`` counts
    blank / "Unknown" / "to-verify" cells and ``red`` counts rows whose license is
    a confirmed-restrictive one still sitting in the catalog (0 after a blacklist
    move). Used by the Sourcing page's Licenses tab.
    """
    from ..ingestion.license_gate import license_verdict

    rows = catalog_rows()
    filled = unknown = red = 0
    for r in rows:
        lic = (r.get("License") or "").strip()
        if not lic or lic.lower() in ("unknown", "to-verify", "n/a", "none", "tbd"):
            unknown += 1
        else:
            filled += 1
        if license_verdict(lic) == "blocked":
            red += 1
    return {"total": len(rows), "filled": filled, "unknown": unknown, "red": red}


def blank_license_links() -> list[str]:
    """Source links of catalog rows whose license is blank / unresolved.

    Mirrors the ``unknown`` bucket of :func:`license_coverage` (blank / "Unknown" /
    "to-verify" / "n/a" / "none" / "tbd"). Used by the Sourcing page to delete every
    source whose license could not be resolved in one action.
    """
    out: list[str] = []
    for r in catalog_rows():
        lic = (r.get("License") or "").strip().lower()
        if lic in ("", "unknown", "to-verify", "n/a", "none", "tbd"):
            link = _row_link(r)
            if link:
                out.append(link)
    return out


def raw_subdomains() -> list[str]:
    """Sorted Sub-Domains that have fetched data under ``data/raw/`` (for clean)."""
    raw = os.path.join(_root(), "data", "raw")
    if not os.path.isdir(raw):
        return []
    try:
        return sorted(d.name for d in os.scandir(raw) if d.is_dir())
    except OSError:
        return []


_LINK_KEYS = ("dataset link", "url", "link", "dataset_link", "source url")


def _row_link(row: dict) -> str:
    """The catalog row's source URL (its ``Dataset Link``), searched flexibly."""
    for k, v in row.items():
        if str(k).strip().lower() in _LINK_KEYS:
            return str(v).strip()
    return ""


def ingest_source_rows() -> list[dict]:
    """Catalog rows for the ingest row-picker, in ``Sources.csv`` file order.

    Every catalog row is included so a row-number range lines up with the
    ``Sources.csv`` row numbers exactly. Each entry is ``{"subdomain", "label",
    "id"}`` where ``id`` is the row's Dataset Link (== the descriptor key
    ``run_ingest`` filters on); a row with no link keeps ``id == ""`` (it
    contributes nothing to a selection but still occupies its row number).
    """
    out: list[dict] = []
    for r in catalog_rows():
        link = _row_link(r)
        dom = (r.get("Sub-Domain") or "").strip() or "Uncategorized"
        name = (r.get("Name") or "").strip() or link or "(no link)"
        out.append({"subdomain": dom, "label": name[:60], "id": link})
    return out


def clean_source_rows() -> list[dict]:
    """Raw source folders for the clean row-picker, in stable (sub-domain, source)
    order.

    Each entry is ``{"subdomain", "source", "label", "id"}`` where ``id`` is the
    ``<sub-domain>/<source>`` folder path that ``run_clean`` cleans. Enumerates the
    two-level ``data/raw/<sub-domain>/<source>`` tree with plain directory listings
    (no per-file size walk), so opening the clean config modal is instant even when
    ``data/raw`` is 100+ GB - unlike :func:`raw_table`, which measures on-disk bytes.
    Only folders that actually hold a ``.jsonl`` file are listed, so the picker
    offers the sources that have data to clean (matching the funnel's raw count) and
    skips folders that were created during ingest but produced no records.
    """
    raw_root = os.path.join(_root(), "data", "raw")
    if not os.path.isdir(raw_root):
        return []
    rows: list[dict] = []
    try:
        for dom in os.scandir(raw_root):
            if not dom.is_dir() or dom.name.startswith("."):
                continue
            for src in os.scandir(dom.path):
                if not src.is_dir() or src.name.startswith("."):
                    continue
                if not _folder_has_jsonl(src.path):
                    continue
                rows.append({"subdomain": dom.name, "source": src.name,
                             "label": f"{dom.name} / {src.name}",
                             "id": f"{dom.name}/{src.name}"})
    except OSError:
        return rows
    rows.sort(key=lambda r: (r["subdomain"].lower(), r["source"].lower()))
    return rows


def latest_source_summary() -> dict | None:
    """Newest sourcing-run summary (``logs/discovered/summary-*.json``), or None.

    Written by :func:`cybersec_slm.sourcing.run.discover`; carries the per-keyword
    hit/new counts so the Sourcing page can show which keywords ran.
    """
    paths = sorted(glob.glob(os.path.join(_logs(), "discovered", "summary-*.json")))
    return _read_json(paths[-1]) if paths else None


def _cat_num(v) -> float:
    """Parse a catalog numeric cell (tolerates commas / blanks) to a float."""
    try:
        return float(str(v).replace(",", "").strip())
    except (TypeError, ValueError):
        return 0.0


def _cat_yes(v) -> bool:
    return str(v or "").strip().lower() in ("yes", "true", "y", "1")


def catalog_totals() -> dict:
    """Authoritative line/size totals from the catalog (fast, avoids scanning data/).

    The catalog keeps per-source ``Total Lines`` / ``Cleaned Lines`` and sizes that
    the ledger and a full corpus scan agree with, so the funnel reads them here
    instead of walking the (100+ GB, dozens-of-millions-of-records) raw tree on
    every page load. Zeros when no catalog is present.
    """
    rows = catalog_rows()
    return {
        "raw_lines": int(sum(_cat_num(r.get("Total Lines")) for r in rows)),
        "raw_size_mb": sum(_cat_num(r.get("JSONL Size (MB)")) for r in rows),
        "cleaned_lines": int(sum(_cat_num(r.get("Cleaned Lines")) for r in rows)),
        "cleaned_size_mb": sum(_cat_num(r.get("Cleaned Size (MB)")) for r in rows),
    }


def ingest_progress() -> dict:
    """Ingest coverage: sources checked and how many produced data, vs the total.

    ``checked`` is how many sources the ingest stage has processed (from the
    resume ledger ``completed_sources.txt``), which includes ones that were then
    skipped (license-blocked, failed fetch, or no usable content). ``with_data``
    is how many actually produced records under ``data/raw/`` (a folder holding a
    ``.jsonl`` file); a folder that was created but yielded nothing is not counted.
    ``total`` is the catalog size. So "184 checked, 149 with data, of 192" reads
    correctly: nearly every source was tried; not all yielded a downloadable
    corpus. Falls back to the on-disk folder count when the ledger is absent.
    """
    with_data = _count_source_dirs(os.path.join(_root(), "data", "raw"),
                                   require_data=True)
    checked = _completed_count() or with_data
    total = _catalog_total() or 0
    return {"checked": checked, "with_data": with_data, "total": total}


def _jsonl_stats(path: str) -> tuple[int, int]:
    """``(.jsonl file count, total bytes)`` under a directory tree.

    Measures the *corpus* — the .jsonl files ingestion produced and cleaning
    consumes — not everything on disk. A source that unpacked an archive can
    leave millions of files behind in its ``_z`` scratch dir (see
    :data:`cybersec_slm.cleaning.common.SCRATCH_DIRS`); those are neither corpus
    nor worth a ``stat`` each, and pruning them is what keeps this walk fast.
    """
    from ..cleaning.common import SCRATCH_DIRS

    files = 0
    total = 0
    try:
        for r, dirs, fs in os.walk(path):
            dirs[:] = [d for d in dirs if d not in SCRATCH_DIRS]
            for f in fs:
                if not f.lower().endswith(".jsonl"):
                    continue
                try:
                    total += os.path.getsize(os.path.join(r, f))
                    files += 1
                except OSError:
                    pass
    except OSError:
        pass
    return files, total


def raw_table() -> list[dict]:
    """Per-source rows for the .jsonl corpus under ``data/raw/`` (file count + size).

    One row per ``<sub-domain>/<source>`` folder, so the table maps the folder
    tree exactly. ``files`` / ``size_mb`` describe the .jsonl corpus (what was
    actually ingested and will be cleaned), so they line up with the Records
    column beside them; fetch scratch on disk is neither counted nor measured.
    Record counts are omitted because counting them means reading every JSONL
    line (minutes).
    """
    raw_root = os.path.join(_root(), "data", "raw")
    if not os.path.exists(raw_root):
        return []
    rows: list[dict] = []
    try:
        for dom in os.scandir(raw_root):
            if not dom.is_dir() or dom.name.startswith("."):
                continue
            for src in os.scandir(dom.path):
                if not src.is_dir() or src.name.startswith("."):
                    continue
                files, total = _jsonl_stats(src.path)
                rows.append({"sub-domain": dom.name, "source": src.name,
                             "files": files, "size_mb": total / (1024 * 1024)})
    except OSError:
        return rows
    rows.sort(key=lambda r: r["size_mb"], reverse=True)
    return rows


def _short_reason(kind: str, raw: str) -> str:
    """Turn a raw log/ledger failure string into a short human reason."""
    if kind == "timed out":
        m = re.search(r"exceeded (\d+)\s*s", raw)
        return f"timed out (over {m.group(1)}s)" if m else "timed out"
    for code, label in (("403", "blocked (403 Forbidden)"),
                        ("404", "missing (404 Not Found)"),
                        ("401", "unauthorized (401)"),
                        ("500", "server error (500)")):
        if code in raw:
            return label
    if "crawl rc=0" in raw:
        return "crawl returned nothing"
    return (raw.split(":", 1)[0].strip() or "fetch failed")[:60]


def ingest_outcome() -> dict:
    """Per-source outcome of the most recent ingest run: why sources produced no data.

    Combines the SQLite ledger's non-ok rows with the ``FAILED`` / ``TIMEOUT``
    lines and the ``ingest: done ok=.. failed=.. rejected=.. timed_out=..`` summary
    in the newest pipeline log. Returns::

        {"summary": {"ok","failed","rejected","timed_out","skipped"} | None,
         "issues": [{"source","kind","reason"} ...]}

    A resume run only re-attempts the sources it hadn't fetched, so this reflects
    the latest attempt, not the whole catalog's history. Empty when nothing ran.
    """
    issues: dict[str, dict] = {}

    # Ledger first: persistent per-source non-ok statuses (e.g. empty crawl).
    db_path = os.path.join(_logs(), "ingest_log.sqlite")
    if os.path.exists(db_path):
        try:
            with sqlite3.connect(db_path) as con:
                for name, status in con.execute(
                        "SELECT name, status FROM ingest "
                        "WHERE status NOT LIKE 'ok%'"):
                    src = (name or "").split("/")[0].strip() or name
                    issues[src] = {"source": src, "kind": "rejected",
                                   "reason": _short_reason("rejected", status or "")}
        except sqlite3.Error:
            pass

    # Log next: fetch failures and timeouts carry the clearest reasons. Read the
    # RUN's log (see _current_run_log) — a worker's log or a stub would carry no
    # ingest summary at all.
    summary: dict | None = None
    run_log = _current_run_log()
    if run_log:
        try:
            with open(run_log, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            lines = []
        for ln in lines:
            sm = re.search(r"ingest: done ((?:\w+=\d+\s*)+)", ln)
            if sm:
                summary = {k: int(v) for k, v in
                           re.findall(r"(\w+)=(\d+)", sm.group(1))}
            fm = re.search(r"\bFAILED ([^:]+):\s*(.+)", ln)
            if fm:
                src = fm.group(1).strip()
                issues[src] = {"source": src, "kind": "failed",
                               "reason": _short_reason("failed", fm.group(2))}
            tm = re.search(r"\bTIMEOUT ([^:]+):\s*(.+)", ln)
            if tm:
                src = tm.group(1).strip()
                issues[src] = {"source": src, "kind": "timed out",
                               "reason": _short_reason("timed out", tm.group(2))}

    ordered = sorted(issues.values(), key=lambda d: (d["kind"], d["source"]))
    return {"summary": summary, "issues": ordered}


def _descriptor_base(d: dict) -> str:
    """The data/raw folder name a source descriptor fetches into.

    Mirrors the fetch layer: dataset kinds land under their owner (hf/kaggle) or
    file name (url/github); everything else lands under its slug.
    """
    kind = d.get("kind")
    ref = d.get("ref") or ""
    if kind in ("hf", "kaggle"):
        return ref.split("/")[0]
    if kind in ("url", "github"):
        return ref.split("/")[-1]
    return d.get("slug") or ""


def _folder_has_jsonl(folder: str) -> bool:
    """True if the folder (or one level down) holds a .jsonl file. Cheap + bounded."""
    if not os.path.isdir(folder):
        return False
    try:
        for e in os.scandir(folder):
            if e.is_file() and e.name.endswith(".jsonl"):
                return True
            if e.is_dir():
                for e2 in os.scandir(e.path):
                    if e2.is_file() and e2.name.endswith(".jsonl"):
                        return True
    except OSError:
        pass
    return False


def _catalog_meta_by_folder() -> dict:
    """Map ``(sub-domain, data/raw folder) -> {name, license, records, size_mb}``.

    The per-source catalog facts the Ingest table shows next to each source's
    on-disk result. Like :func:`_catalog_lines_by_folder` this joins catalog rows
    to their fetch folder through the ingestion descriptor loader, but carries the
    display fields (Name, License) too. Empty when the catalog can't be read.
    """
    try:
        from ..ingestion import sources as _srcs
    except Exception:
        return {}
    catalog = _catalog_path()
    if not os.path.exists(catalog):
        return {}

    by_ident: dict[str, dict] = {}
    for r in catalog_rows():
        ident = _srcs.source_identity(_row_link(r))
        if ident:
            by_ident[ident] = {
                "name": (r.get("Name") or "").strip(),
                "license": (r.get("License") or "").strip(),
                "records": int(_cat_num(r.get("Total Lines"))),
                "size_mb": _cat_num(r.get("JSONL Size (MB)")),
            }
    try:
        descs = _srcs.load_descriptors(catalog, order_by_size=False)
    except Exception:
        return {}

    out: dict[tuple[str, str], dict] = {}
    for d in descs:
        base = _descriptor_base(d)
        if not base:
            continue
        meta = by_ident.get(_srcs.source_identity(d.get("url") or d.get("start_url")))
        if meta is not None:
            out[(d.get("domain", ""), base)] = meta
    return out


# Ingest status -> the wording the UI shows. "ingested" is the only success.
INGEST_STATUSES = ("ingested", "license", "failed", "timed out", "rejected",
                   "no records")


def ingest_table(raw_rows: list[dict] | None = None) -> list[dict]:
    """Every catalogued source joined to its ingest result — the full Ingest table.

    Reconciles the whole catalog against ``data/raw/``: each source gets a
    ``status`` (``ingested`` when a JSONL file landed on disk, otherwise why not),
    its catalog ``records`` / ``license``, and its measured on-disk ``size_mb`` /
    ``files``. Reasons come from the commercial-license gate (the common case:
    non-commercial / copyleft / unrecognised licenses are turned away before
    download) and, for sources fetched that yielded nothing, the latest run's
    failure log.

    ``raw_rows`` is :func:`raw_table` output; pass the cached copy (walking
    ``data/raw`` is a 100+ GB scan) or omit it to measure now. A source with no
    folder on disk reports 0 files and falls back to its catalog size, so a
    license-blocked row still shows what it would have cost.

    Each row is ``{"sub-domain", "source", "name", "status", "reason", "records",
    "size_mb", "files", "license"}``, sorted by size (biggest first) with the
    ingested sources ahead of the ones that produced nothing.
    """
    try:
        from ..ingestion import sources as _srcs
        from ..ingestion.license_gate import is_license_ok
    except Exception:
        return []
    catalog = _catalog_path()
    if not os.path.exists(catalog):
        return []
    try:
        descs = _srcs.load_descriptors(catalog, order_by_size=False)
    except Exception:
        return []

    raw_root = os.path.join(_root(), "data", "raw")
    disk = {(r["sub-domain"], r["source"]): r
            for r in (raw_table() if raw_rows is None else raw_rows)}
    meta = _catalog_meta_by_folder()
    fails = {i["source"]: i for i in ingest_outcome().get("issues", [])}

    out: list[dict] = []
    for d in descs:
        dom, base = d.get("domain", ""), _descriptor_base(d)
        m = meta.get((dom, base), {})
        on_disk = disk.get((dom, base), {})
        row = {
            "sub-domain": dom,
            "source": base,
            "name": m.get("name", "") or base,
            "records": m.get("records", 0),
            "size_mb": on_disk.get("size_mb", m.get("size_mb", 0.0)),
            "files": on_disk.get("files", 0),
            "license": m.get("license", "") or (d.get("license") or ""),
        }
        if _folder_has_jsonl(os.path.join(raw_root, dom, base)):
            out.append({**row, "status": "ingested", "reason": ""})
            continue
        # Nothing on disk: report why, and don't credit it with catalog records.
        row["records"] = 0
        licok, lreason = is_license_ok(d)
        if not licok:
            out.append({**row, "status": "license", "reason": lreason})
            continue
        key = d.get("slug") or (d.get("ref") or "").split("/")[-1] or base
        hit = fails.get(key) or fails.get(base)
        if hit:
            out.append({**row, "status": hit["kind"], "reason": hit["reason"]})
        else:
            out.append({**row, "status": "no records",
                        "reason": "fetched but produced no records "
                                  "(failed, timed out, or empty)"})
    out.sort(key=lambda r: (r["status"] != "ingested", -r["size_mb"],
                            r["sub-domain"], r["source"]))
    return out


def sources_without_data() -> list[dict]:
    """Every catalogued source that produced no records, each with the reason.

    The non-``ingested`` rows of :func:`ingest_table`, in that table's shape:
    ``{"sub-domain", "source", "type", "reason"}`` where ``type`` is ``license``,
    ``failed``, ``timed out``, ``rejected``, or ``no records``.

    ``raw_rows=[]`` skips the ``data/raw`` byte walk: this view drops the size /
    files columns that walk feeds, and a source reported here has no data on disk
    to measure anyway.
    """
    out = [{"sub-domain": r["sub-domain"], "source": r["source"],
            "type": r["status"], "reason": r["reason"]}
           for r in ingest_table(raw_rows=[]) if r["status"] != "ingested"]
    out.sort(key=lambda r: (r["type"], r["sub-domain"], r["source"]))
    return out


def cleaned_table() -> list[dict]:
    """Per-source cleaned rows read straight from ``data/clean/`` (records + size).

    Gives the Clean page a real table even before a ``clean_report.csv`` exists:
    one row per ``<sub-domain>/<source>`` folder with its JSONL record count and
    size on disk. Empty when nothing has been cleaned yet.
    """
    clean_root = os.path.join(_root(), "data", "clean")
    if not os.path.exists(clean_root):
        return []
    out: list[dict] = []
    try:
        for dom in os.scandir(clean_root):
            if not dom.is_dir() or dom.name.startswith("."):
                continue
            for src in os.scandir(dom.path):
                if not src.is_dir() or src.name.startswith("."):
                    continue
                out.append({
                    "sub-domain": dom.name,
                    "source": src.name,
                    "records": _count_jsonl_records(src.path),
                    "size (MB)": round(_dir_size_mb(src.path), 2),
                })
    except OSError:
        return out
    out.sort(key=lambda r: r["records"], reverse=True)
    return out


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


def full_log(log: str | None = None) -> list[str]:
    """Full contents of a pipeline log session, newest by default."""
    logs = _pipeline_logs()
    if not logs:
        return []
    if log is None:
        path = logs[-1]
    else:
        path = log if os.path.isabs(log) else os.path.join(_logs(), log)
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return [ln.rstrip("\n") for ln in f.readlines()]
    except OSError:
        return []


def _completed_count() -> int:
    """Number of sources finished this run (lines in the resume ledger)."""
    ledger = os.path.join(_logs(), "completed_sources.txt")
    if not os.path.exists(ledger):
        return 0
    try:
        with open(ledger, encoding="utf-8") as f:
            return sum(1 for ln in f if ln.strip())
    except OSError:
        return 0


def live_progress(tail: int = 40) -> dict:
    """Sources completed so far (from the resume ledger) + a log tail.

    ``completed`` counts ``logs/completed_sources.txt`` (each source is appended as
    it finishes, cleaned or license-skipped); ``total`` is the catalog size when
    it can be located, else None (the UI shows a bare count).
    """
    return {"completed": _completed_count(), "total": _catalog_total(),
            "log_tail": log_tail(tail)}


def checkpoint_status() -> dict:
    """Resume-ledger state for the Overview: is there saved progress to resume from.

    Reads ``logs/completed_sources.txt`` cheaply (no log tail, unlike
    :func:`live_progress`). ``exists`` is True once any source has been recorded,
    which is exactly what the ``Resume`` button continues from; ``completed`` /
    ``total`` let the UI say "N of M sources saved".
    """
    completed = _completed_count()
    return {"exists": completed > 0, "completed": completed,
            "total": _catalog_total()}


def session_history(limit: int = 15) -> list[dict]:
    """Recent pipeline sessions, newest first (one per ``pipeline.<pid>.log``).

    Each row: the process id (the "session number", which is also the log file's
    name), when it started, seconds since its last activity, its log size, and
    whether it is the current active run. Lets the UI point at a specific log file.
    """
    cur = run_status()
    cur_pid = cur.get("pid")
    running = cur.get("state") == "running"
    now = time.time()
    out: list[dict] = []
    for p in sorted(_pipeline_logs(), key=os.path.getmtime, reverse=True)[:limit]:
        name = os.path.basename(p)
        m = re.search(r"pipeline\.(\d+)\.log", name)
        pid = int(m.group(1)) if m else None
        try:
            mtime, size = os.path.getmtime(p), os.path.getsize(p)
        except OSError:
            mtime, size = now, 0
        ts = None
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                ts = _parse_log_ts(f.readline())
        except OSError:
            pass
        out.append({
            "pid": pid, "log": name,
            "started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "",
            "age_s": now - mtime, "size_kb": round(size / 1024, 1),
            "current": bool(pid == cur_pid and running),
        })
    return out


def _parse_log_ts(s: str) -> float | None:
    """Parse a ``YYYY-MM-DD HH:MM:SS`` prefix (control file / loguru line) to epoch."""
    if not s:
        return None
    try:
        return time.mktime(time.strptime(s.strip()[:19], "%Y-%m-%d %H:%M:%S"))
    except (ValueError, OverflowError):
        return None


def _run_started_at() -> float | None:
    """Epoch start time of the current/last run.

    Prefers the dashboard control file's ``started_at`` (exact for runs launched
    from the dashboard); falls back to the first timestamp of the run's own log
    (a CLI run has no control file). Returns None when neither is available.
    """
    from . import control
    ts = _parse_log_ts((control.status() or {}).get("started_at") or "")
    if ts is not None:
        return ts
    run_log = _current_run_log()
    if not run_log:
        return None
    try:
        with open(run_log, encoding="utf-8", errors="replace") as f:
            first = f.readline()
    except OSError:
        return None
    return _parse_log_ts(first.split("|", 1)[0] if "|" in first else first)


def stage_progress_sample() -> dict | None:
    """One cheap scalar of what the LIVE stage has produced so far.

    ``{"stage", "label", "value", "unit", "what"}`` — or None when nothing is
    running, or the live stage has no meaningful throughput to sample.

    Each stage is measured in the unit it actually moves, which is why this is a
    per-stage lookup rather than one number: sourcing accumulates catalog rows,
    ingest finishes sources, clean grows ``data/clean`` on disk, and schema grows
    the final dataset. EDA is a single scan with no incremental output, so it has
    no sample.

    Every branch must stay cheap enough to call once a second: this is sampled to
    derive a rate, so an expensive read here would cost more than the work it
    measures. That rules out record counts (reading every byte of data/clean) in
    favour of bytes on disk.
    """
    if run_status()["state"] != "running":
        return None
    key = (run_phase() or {}).get("phase")
    if key == "source":
        return {"stage": key, "label": "Sourcing", "unit": "rows",
                "what": "catalog rows discovered",
                "value": float(_catalog_total() or 0)}
    if key == "ingest":
        return {"stage": key, "label": "Ingest", "unit": "sources",
                "what": "sources fetched",
                "value": float(_completed_count())}
    if key == "clean":
        return {"stage": key, "label": "Clean", "unit": "MB",
                "what": "cleaned output on disk",
                "value": _dir_size_mb(os.path.join(_root(), "data", "clean"))}
    if key == "schema":
        path = os.path.join(_final(), "dataset.jsonl")
        size = os.path.getsize(path) / (1024 * 1024) if os.path.exists(path) else 0.0
        return {"stage": key, "label": "Schema", "unit": "MB",
                "what": "final dataset written", "value": size}
    return None


def stage_timeline() -> list[dict]:
    """When each stage of the current/last run started and stopped.

    One row per stage the run actually reached::

        [{"stage", "label", "start_s", "end_s", "duration_s", "running"}, ...]

    ``start_s`` / ``end_s`` are seconds since the run's first log line, so the x
    axis is "time since the run began" and needs no wall-clock conversion. A stage
    ends where the next one begins; the furthest stage reached runs to *now* while
    the run is live, and to its last log line once it is not.

    Read from the run's own log (see :func:`_current_run_log`) using the canonical
    markers in :mod:`cybersec_slm.stages`, so it works for a dashboard run and a
    bare CLI run alike. Stages that were skipped (a ``--resume`` plan drops
    ``source``) never appear, because they never logged. Empty when no run has
    logged anything.
    """
    path = _current_run_log()
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return []

    # First timestamped line is t=0. A loguru line is "<ts> | LEVEL | ...".
    stamped: list[tuple[float, str]] = []
    for ln in lines:
        ts = _parse_log_ts(ln.split("|", 1)[0] if "|" in ln else ln)
        if ts is not None:
            stamped.append((ts, ln))
    if not stamped:
        return []
    t0 = stamped[0][0]
    last_ts = stamped[-1][0]

    # Earliest timestamp at which each stage's marker appears.
    starts: dict[str, float] = {}
    for ts, ln in stamped:
        for stage in stages.STAGES:
            if stage.key in starts:
                continue
            if any(m in ln for m in stage.markers):
                starts[stage.key] = ts

    if not starts:
        return []
    # Pipeline order, not first-seen order: a later stage's marker can appear in
    # an earlier stage's chatter, and the spine is the truth about progression.
    ordered = [(k, starts[k]) for k in stages.stage_keys() if k in starts]
    live = run_status()["state"] == "running"
    now = time.time()

    out: list[dict] = []
    for i, (key, start) in enumerate(ordered):
        if i + 1 < len(ordered):
            end = ordered[i + 1][1]           # ends where the next stage begins
            running = False
        else:
            end = now if live else last_ts    # the furthest stage reached
            running = live
        out.append({
            "stage": key,
            "label": stages.get_stage(key).label,
            "start_s": max(start - t0, 0.0),
            "end_s": max(end - t0, 0.0),
            "duration_s": max(end - start, 0.0),
            "running": running,
        })
    return out


# Per-source raw .jsonl bytes, memoized: the clean ETA needs them every refresh
# and data/raw does not change while cleaning runs.
_RAW_SIZES_TTL_S = 60.0
_raw_sizes_cache: tuple[float, dict[str, int]] | None = None


def _raw_sizes_by_sid() -> dict[str, int]:
    """``{"<sub-domain>/<source>": jsonl_bytes}`` for every raw source with data."""
    global _raw_sizes_cache
    now = time.monotonic()
    if _raw_sizes_cache is not None and now - _raw_sizes_cache[0] < _RAW_SIZES_TTL_S:
        return _raw_sizes_cache[1]
    raw_root = os.path.join(_root(), "data", "raw")
    sizes: dict[str, int] = {}
    if os.path.isdir(raw_root):
        try:
            for dom in os.scandir(raw_root):
                if not dom.is_dir() or dom.name.startswith("."):
                    continue
                for src in os.scandir(dom.path):
                    if not src.is_dir() or src.name.startswith("."):
                        continue
                    files, total = _jsonl_stats(src.path)
                    if files:
                        sizes[f"{dom.name}/{src.name}"] = total
        except OSError:
            pass
    _raw_sizes_cache = (now, sizes)
    return sizes


def _cleaned_ledger_sids() -> list[str]:
    """Sources recorded cleaned, in the order they finished (append-only)."""
    path = os.path.join(_logs(), "cleaned_sources.txt")
    try:
        with open(path, encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip()]
    except OSError:
        return []


def _resume_skipped() -> int:
    """How many sources this run's clean stage skipped as already cleaned.

    The ledger spans every resume, so it cannot say what *this* run has done. The
    run logs the skip count at startup and the ledger is append-only, so the
    entries past that mark are exactly this run's work.
    """
    path = _current_run_log()
    if not path or not os.path.exists(path):
        return 0
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for ln in f:
                m = re.search(r"clean: resume skipping (\d+) already-cleaned", ln)
                if m:
                    return int(m.group(1))
    except OSError:
        pass
    return 0


def _clean_workers() -> int:
    """Worker count this run's clean pass reported (1 when it did not say)."""
    path = _current_run_log()
    if not path or not os.path.exists(path):
        return 1
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for ln in f:
                m = re.search(r"clean: parallelizing over (\d+) workers", ln)
                if m:
                    return max(int(m.group(1)), 1)
    except OSError:
        pass
    return 1


def clean_eta(elapsed_s: float) -> tuple[float | None, str]:
    """``(remaining_seconds, basis)`` for the clean stage, measured in bytes.

    Source count is the wrong unit: sources span a kilobyte to twenty gigabytes,
    so "N of M sources" projects nonsense. Cleaning cost tracks records, and raw
    .jsonl bytes are the cheapest close proxy.

    Two corrections make this honest rather than merely linear:

    * Only *this* run's sources count toward the rate (see :func:`_resume_skipped`);
      dividing every resume's work by this run's elapsed would inflate it.
    * The tail is bounded by the single biggest remaining source, because the pool
      parallelises per source and one file is cleaned by one worker. A purely
      linear projection promises a finish the scheduler cannot deliver, so the
      estimate is the larger of the two.
    """
    sizes = _raw_sizes_by_sid()
    if not sizes:
        # No per-source signal to project from (raw purged, or already consumed).
        return None, "finalizing"
    ledger = _cleaned_ledger_sids()
    done_this_run = ledger[_resume_skipped():]
    done_bytes = sum(sizes.get(s, 0) for s in done_this_run)
    if elapsed_s <= 0 or done_bytes <= 0:
        return None, "clean-warmup"          # nothing finished yet: no rate to use

    remaining = {s: n for s, n in sizes.items() if s not in set(ledger)}
    if not remaining:
        # Every source is cleaned, but the phase is still `clean`: this is the
        # cross-source dedup tail, whose cost has nothing to do with the per-source
        # rate. Saying "0 seconds" here would claim the run is done while a long
        # pass is still going, so name the tail instead of inventing a number.
        return None, "finalizing"
    rate = done_bytes / elapsed_s                       # bytes/s, all workers
    linear = sum(remaining.values()) / rate
    # One source cannot go faster than one worker.
    per_worker = rate / _clean_workers()
    tail = max(remaining.values()) / per_worker if per_worker > 0 else 0.0
    return max(linear, tail), "clean-bytes"


def run_timing() -> dict:
    """Elapsed time since the run started, plus a rough projected total runtime.

    Returns ``{"elapsed_s", "eta_s", "total_s", "basis"}``. ``elapsed_s`` is seconds
    since the run's start (None if no start time is known). ``eta_s`` is the linear
    projection of *remaining* time (``elapsed / completed * (total - completed)``);
    ``total_s`` is the projected *full* start-to-end runtime (``elapsed + eta_s``,
    i.e. ``elapsed / completed * total``), which the UI shows because a total
    duration reads as far less jumpy than a remaining-time countdown. Both are
    computed only during the ingest phase, which is ~80% of wall-clock and the only
    stage driven by source count; once ingestion is done the tail (dedup -> EDA ->
    normalize) is not source-count driven, so both are None and ``basis`` says
    ``finalizing`` rather than faking a number. Sources vary hugely in size, so
    treat the projection as an estimate only.
    """
    start = _run_started_at()
    elapsed_s = (time.time() - start) if start is not None else None
    pkey = (run_phase() or {}).get("phase")
    completed, total = _completed_count(), _catalog_total()

    eta_s: float | None = None
    total_s: float | None = None
    if elapsed_s is None:
        basis = "no-start"
    elif pkey == "gate_failed":
        basis = "finished"
    elif pkey == "ingest" and total and completed:
        eta_s = max(elapsed_s / completed * (total - completed), 0.0)
        total_s = elapsed_s + eta_s
        basis = "ingest-linear"
    elif pkey == "clean":
        # Clean is the long pole on a large corpus, so "finalizing" was the least
        # useful thing to say for the stage that takes the most wall-clock.
        eta_s, basis = clean_eta(elapsed_s)
        if eta_s is not None:
            total_s = elapsed_s + eta_s
    elif pkey in ("eda", "schema"):
        basis = "finalizing"
    else:
        basis = "starting"
    return {"elapsed_s": elapsed_s, "eta_s": eta_s, "total_s": total_s,
            "basis": basis}


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


# Every counter the cleaning pass records, as (report column, label, what it means).
# Mirrors cleaning.pipeline.REPORT_COLS; ordered as the stages actually run, so the
# UI reads top-to-bottom like the pipeline: map -> sanitize -> anomaly -> dedup ->
# PII -> language.
CLEAN_COUNTERS: tuple[tuple[str, str, str], ...] = (
    ("in", "Records in", "Raw records read from data/raw/"),
    ("out", "Records out", "Records written to data/clean/"),
    ("mapped_text", "Text mapped", "Prose built from a non-`text` column"),
    ("excluded_no_text", "No prose column",
     "Feature-table rows with no prose to clean; excluded from the text corpus"),
    ("sanitized", "Sanitized", "Records whose text was repaired or normalized"),
    ("struct_fixed", "Structurally fixed",
     "Records sanitize rescued that would otherwise have been dropped"),
    ("struct_dropped", "Structurally dropped",
     "Empty, under the length floor, or unparseable"),
    ("behavioral_flagged", "Behaviorally flagged",
     "Garbage ratio / repetition / length — routed to flagged/ for review"),
    ("exact_dups", "Exact duplicates", "Byte-identical text already seen"),
    ("near_dups", "Near duplicates", "Fuzzy MinHash match against a kept record"),
    ("pii_redacted", "PII redacted",
     "Records with at least one identifier replaced by a typed placeholder "
     "(<EMAIL_ADDRESS>, <IP_ADDRESS>, ...)"),
    ("translated", "Translated", "Non-English records translated into English and kept"),
    ("non_en_dropped", "Non-English dropped",
     "Non-English and untranslatable (or dropped by policy)"),
)


def clean_stats() -> dict:
    """The cleaning pass's TOTAL counters as ints, plus derived rates.

    Reads the TOTAL row of ``logs/clean_report.csv`` — every counter in
    :data:`CLEAN_COUNTERS` (PII redacted, translated, dups, each drop mechanism)
    rather than only the in/out the funnel shows. Returns
    ``{"counts": {col: int}, "kept_pct": float, "files": int, "has_report": bool}``;
    ``has_report`` is False on a fresh checkout (counts all zero), which lets the
    UI say "no clean run yet" instead of rendering a wall of zeros.
    """
    rc = clean_report()
    total = rc.get("total") or {}
    counts = {col: _to_int(total, col) for col, _lbl, _help in CLEAN_COUNTERS}
    kept = (100 * counts["out"] / counts["in"]) if counts["in"] else 0.0
    return {"counts": counts, "kept_pct": round(kept, 1),
            "files": len(rc.get("files") or []), "has_report": bool(rc.get("total"))}


def clean_table() -> list[dict]:
    """Per-source cleaning stats — every counter, aggregated from the clean report.

    One row per ``<sub-domain>/<source>`` with each :data:`CLEAN_COUNTERS` column
    summed over that source's files, plus ``kept_pct``. Unlike
    :func:`cleaned_table` (which measures what is physically under ``data/clean/``)
    this reports what the cleaning pass *did* — how many records each mechanism
    removed — so it is empty until a clean run writes ``logs/clean_report.csv``.
    Sorted by records-in, biggest first.
    """
    cols = [c for c, _l, _h in CLEAN_COUNTERS]
    agg: dict[tuple[str, str], dict] = {}
    for r in clean_report().get("files") or []:
        key = (r.get("sub_domain", ""), r.get("source", ""))
        a = agg.setdefault(key, {"sub-domain": key[0], "source": key[1],
                                 **{c: 0 for c in cols}})
        for c in cols:
            a[c] += _to_int(r, c)
    out: list[dict] = []
    for a in agg.values():
        kept = (100 * a["out"] / a["in"]) if a["in"] else 0.0
        out.append({**a, "kept_pct": round(kept, 1)})
    out.sort(key=lambda r: r["in"], reverse=True)
    return out


def normalize_report() -> dict | None:
    """Parsed ``logs/normalize_report.json`` (counts, paused sources, categories)."""
    return _read_json(os.path.join(_logs(), "normalize_report.json"))


def manifest() -> dict | None:
    """Parsed ``data/final/manifest.json`` (the release datasheet)."""
    return _read_json(os.path.join(_final(), "manifest.json"))


def _dir_size_mb(path: str) -> float:
    if not os.path.exists(path):
        return 0.0
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total / (1024 * 1024)


# Per-file record-count memo: path -> (mtime, size, count). A cleaned .jsonl is
# written once and then left alone, so its count cannot change while its (mtime,
# size) identity holds. Without this, one count of data/clean re-read every byte
# (32s at 9.5 GB, and it grows with the corpus) — on a 20s refresh the Overview
# could never keep up with itself, which is what made the dashboard crawl during a
# run. Bounded by the number of .jsonl files (hundreds), so it stays small.
_JSONL_COUNT_MEMO: dict[str, tuple[float, int, int]] = {}


def _count_file_records(path: str) -> int:
    """Non-empty records in one .jsonl, re-read only when the file changed."""
    try:
        stat = os.stat(path)
    except OSError:
        return 0
    hit = _JSONL_COUNT_MEMO.get(path)
    if hit is not None and hit[0] == stat.st_mtime and hit[1] == stat.st_size:
        return hit[2]
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            count = sum(1 for ln in f if ln.strip())
    except OSError:
        return 0
    _JSONL_COUNT_MEMO[path] = (stat.st_mtime, stat.st_size, count)
    return count


def _count_jsonl_records(path: str) -> int:
    """Count non-empty JSONL records under a directory tree.

    Per-file counts are memoized by (mtime, size), so a refresh during a run only
    reads the files the workers actually touched.
    """
    if not os.path.exists(path):
        return 0
    from ..cleaning.common import SCRATCH_DIRS

    count = 0
    try:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in SCRATCH_DIRS]
            for name in files:
                if name.endswith(".jsonl"):
                    count += _count_file_records(os.path.join(root, name))
    except OSError:
        pass
    return count


def _count_source_dirs(path: str, require_data: bool = False) -> int:
    """Count distinct source folders (domain/<source>/) that exist under path.

    With ``require_data=True`` only folders that actually hold a ``.jsonl`` file
    are counted, so a source whose folder was created during ingest but produced
    no records (e.g. an empty crawl) is excluded. This is what "produced data"
    means, versus the bare on-disk folder count.
    """
    if not os.path.exists(path):
        return 0
    count = 0
    try:
        for domain_entry in os.scandir(path):
            if not domain_entry.is_dir() or domain_entry.name.startswith("."):
                continue
            for src_entry in os.scandir(domain_entry.path):
                if not src_entry.is_dir() or src_entry.name.startswith("."):
                    continue
                if require_data and not _folder_has_jsonl(src_entry.path):
                    continue
                count += 1
    except OSError:
        pass
    return count


def _ingest_ledger_stats() -> dict:
    """Best-effort stats from the SQLite ingest ledger for raw-stage history.

    ``sources`` counts distinct sources that actually produced raw output
    (``status`` ok), keyed by source_url (falling back to name), so it matches
    the funnel's per-source meaning instead of counting every produced file or
    counting license-skipped / failed rows.
    """
    db_path = os.path.join(_logs(), "ingest_log.sqlite")
    if not os.path.exists(db_path):
        return {"sources": 0, "lines": 0, "size_mb": 0.0}
    try:
        with sqlite3.connect(db_path) as con:
            rows = con.execute(
                "SELECT COUNT(DISTINCT COALESCE(NULLIF(source_url, ''), name)), "
                "COALESCE(SUM(rows), 0), COALESCE(SUM(orig_mb), 0.0) "
                "FROM ingest WHERE status LIKE 'ok%'"
            ).fetchone()
    except sqlite3.Error:
        return {"sources": 0, "lines": 0, "size_mb": 0.0}
    return {
        "sources": int(rows[0] or 0),
        "lines": int(rows[1] or 0),
        "size_mb": float(rows[2] or 0.0),
    }


def _catalog_lines_by_folder() -> dict:
    """Map ``(sub-domain, data/raw folder name) -> (Total Lines, JSONL Size MB)``.

    Uses the ingestion descriptor loader to derive each catalog row's on-disk
    folder name (the same mapping the fetch layer uses), joined to that row's
    line/size cells by :func:`sources.source_identity`. This lets the funnel read
    per-source catalog figures for exactly the sources present under ``data/raw/``
    without scanning the (100+ GB) raw tree. Empty when the catalog or descriptors
    can't be read; the caller then reports zero records for on-disk sources.
    """
    try:
        from ..ingestion import sources as _srcs
    except Exception:
        return {}
    catalog = _catalog_path()
    if not os.path.exists(catalog):
        return {}

    # identity -> (lines, size_mb) from the raw catalog rows.
    ident_ls: dict[str, tuple[float, float]] = {}
    for r in catalog_rows():
        ident = _srcs.source_identity(_row_link(r))
        if ident:
            ident_ls[ident] = (_cat_num(r.get("Total Lines")),
                               _cat_num(r.get("JSONL Size (MB)")))
    try:
        descs = _srcs.load_descriptors(catalog, order_by_size=False)
    except Exception:
        return {}

    out: dict[tuple[str, str], tuple[float, float]] = {}
    for d in descs:
        base = _descriptor_base(d)
        if not base:
            continue
        ident = _srcs.source_identity(d.get("url") or d.get("start_url"))
        ls = ident_ls.get(ident)
        if ls is not None:
            out[(d.get("domain", ""), base)] = ls
    return out


def _raw_on_disk_totals(measure_size: bool = True) -> dict:
    """Raw-stage totals restricted to sources physically present under ``data/raw/``.

    Iterates the on-disk ``<sub-domain>/<source>`` folders so Sources, Records and
    Size all describe the same population (the data actually on this machine) rather
    than the whole catalog. Only folders that actually hold a ``.jsonl`` file are
    counted, so a folder created during ingest that produced no records is excluded
    (matching "produced data"). Returns ``{"sources", "lines", "size_mb"}`` (all
    zero when no raw tree exists).

    Records are COUNTED ON DISK, not joined from the catalog's ``Total Lines``.
    The catalog was measured against the live corpus and is not trustworthy: it
    claimed 17,972,727 raw records where disk held 44,761,032 (+149%). 242 of the
    370 fetched sources had no catalog figure at all — 14.4M records that the
    funnel simply could not see — and among those it did have, 62 disagreed with
    disk by more than 2% (Microsoft alone by 9.5M). A number that is fast and
    wrong is worse than one that is slow and right, and the count is memoized per
    file by (mtime, size) (:func:`_count_file_records`) then cached on a long TTL
    (:func:`cached.raw_records`), so it is paid once per session.

    ``measure_size=False`` skips both the per-source ``os.walk`` byte count and the
    record scan (the slow parts: raw is ~90 GB of .jsonl), returning ``size_mb`` =
    0.0 and ``lines`` = 0 so the caller can render live *source* counts cheaply and
    fill both from the cached measurements.
    """
    raw_root = os.path.join(_root(), "data", "raw")
    if not os.path.isdir(raw_root):
        return {"sources": 0, "lines": 0, "size_mb": 0.0}

    key_ls = _catalog_lines_by_folder()
    sources = 0
    lines = 0.0
    size_mb = 0.0
    try:
        for dom in os.scandir(raw_root):
            if not dom.is_dir() or dom.name.startswith("."):
                continue
            for src in os.scandir(dom.path):
                if not src.is_dir() or src.name.startswith("."):
                    continue
                if not _folder_has_jsonl(src.path):
                    continue
                sources += 1
                _ln, sz = key_ls.get((dom.name, src.name), (0.0, 0.0))
                # Records are counted, never joined from `_ln` (the catalog's
                # figure): see the docstring — it was 149% wrong on the live
                # corpus and blind to 242 fetched sources. Only the measured path
                # pays for it; the cheap live path defers to cached.raw_records.
                if measure_size:
                    lines += _count_jsonl_records(src.path)
                # Measured size means a walk per source; the cheap live path uses
                # the catalog's per-folder size instead so the funnel can refresh
                # every second without touching the tree.
                size_mb += (_jsonl_stats(src.path)[1] / (1024 * 1024)
                            if measure_size else sz)
    except OSError:
        pass
    return {"sources": sources, "lines": int(lines), "size_mb": size_mb}


def data_funnel(measure_size: bool = True) -> dict:
    """Aggregate Raw -> Cleaned -> Final metrics for the Overview funnel.

    Every figure describes what is physically on disk under the data root (the
    honest per-machine state). Raw *and* cleaned records are counted, never taken
    from the catalog (whose ``Total Lines`` understated the live corpus by 149%)
    nor from the clean report (which describes one pass rather than the corpus —
    see the Cleaned block below). Final counts come from the manifest.

    ``measure_size=False`` skips the byte counts and BOTH record scans, returning
    those figures as 0 so the Overview can refresh live *source* counts every
    second cheaply and fill records/sizes from cached snapshots
    (:func:`cached.raw_records`, :func:`cached.cleaned_records`,
    :func:`cached.raw_size_mb`). Callers that need them (the cached wrappers and
    the per-stage pages) keep the default.
    """
    man = manifest()
    nr = normalize_report()

    # Raw: count the source folders present and derive line totals only for
    # the sources actually on disk, so this metric stays live as the run writes
    # to data/raw/ rather than relying on a stale catalog-wide sum.
    raw_totals = _raw_on_disk_totals(measure_size=measure_size)
    raw_sources = raw_totals["sources"]
    raw_lines = raw_totals["lines"] if raw_sources else 0
    raw_size_mb = raw_totals["size_mb"] if raw_sources else 0.0

    # Cleaned: count what is physically under data/clean/. The clean report's TOTAL
    # is a per-PASS statistic and must NOT be used as the corpus size — a --resume
    # pass rewrites the report from only the sources it cleaned (the rest are
    # skipped via the ledger), and final_global_dedup deletes records from
    # data/clean after the report is written. Disk is the only figure that stays
    # true across resumes and dedup. The per-record scan is memoized per file
    # (see _count_file_records), so a refresh only re-reads what changed; the cheap
    # live path still skips it and the Overview fills it from a short-TTL cache.
    clean_root = os.path.join(_root(), "data", "clean")
    cleaned_size_mb = _dir_size_mb(clean_root)
    cleaned_sources = _count_source_dirs(clean_root)
    cleaned_lines = _count_jsonl_records(clean_root) if measure_size else 0

    # Final: manifest is the canonical source of truth.
    final_file = os.path.join(_final(), "dataset.jsonl")
    appended_size_mb = (os.path.getsize(final_file) / (1024 * 1024)
                        if os.path.exists(final_file) else 0.0)
    appended_lines = man.get("record_count", 0) if man else 0
    appended_sources = len(man.get("sources", {})) if man else 0

    # Normalization losses - shown in the funnel so the cleaned→final drop is explained.
    norm_counts = (nr or {}).get("counts", {})
    synthetic_excluded = int(norm_counts.get("synthetic_excluded", 0))
    near_dups = int(norm_counts.get("near_dups", 0))
    exact_dups = int(norm_counts.get("exact_dups", 0))
    rejected = int(norm_counts.get("rejected", 0))

    return {
        "raw": {"sources": raw_sources, "lines": raw_lines, "size_mb": raw_size_mb},
        "cleaned": {"sources": cleaned_sources, "lines": cleaned_lines, "size_mb": cleaned_size_mb},
        "appended": {
            "sources": appended_sources,
            "lines": appended_lines,
            "size_mb": appended_size_mb,
            "synthetic_excluded": synthetic_excluded,
            "near_dups": near_dups,
            "exact_dups": exact_dups,
            "rejected": rejected,
        },
    }


# ------------------------------------------------------------- loss breakdown -
def _to_int(d: dict, key: str) -> int:
    try:
        return int(d.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


# Per-file clean-report drop columns -> a short human label, in report order.
_CLEAN_DROP_COLS = [
    ("excluded_no_text", "no prose column"),
    ("struct_dropped", "structural (<50 chars / empty / parse error)"),
    ("behavioral_flagged", "behavioral flag (garbage / repeat / length)"),
    ("non_en_dropped", "non-English (untranslatable)"),
    ("exact_dups", "exact duplicate"),
    ("near_dups", "near duplicate"),
]


def loss_breakdown() -> dict:
    """Where records are dropped across the pipeline (the 'where did my data go' view).

    Reads only what the pipeline already writes (clean report, normalize report,
    latest EDA report); no new pipeline outputs. Returns::

        {
          "raw_in": int, "clean_out": int, "final_written": int,
          "stages": [{"stage", "mechanism", "dropped", "kind"} ...],  # ranked-ish
          "per_source": [{"source","sub_domain","in","out","lost","kept_pct",
                          "top_drop_reason"} ...],                    # most lost first
        }

    Empty/zero when the artifacts are absent (fresh checkout).
    """
    rc = clean_report()
    total = rc.get("total") or {}
    files = rc.get("files") or []
    nc = (normalize_report() or {}).get("counts", {}) or {}
    eda = latest_eda() or {}

    raw_in = _to_int(total, "in")
    clean_out = _to_int(total, "out")
    final_written = _to_int(nc, "written")

    stages: list[dict] = [
        {"stage": "clean", "mechanism": "no prose column (excluded_no_text)",
         "dropped": _to_int(total, "excluded_no_text"), "kind": "format"},
        {"stage": "clean", "mechanism": "structural (<50 chars / empty / parse error)",
         "dropped": _to_int(total, "struct_dropped"), "kind": "quality"},
        {"stage": "clean", "mechanism": "behavioral flag (garbage / repeat / length)",
         "dropped": _to_int(total, "behavioral_flagged"), "kind": "quality"},
    ]

    # EDA auto-rebalance (random downsample), only when it actually ran.
    if eda.get("rebalanced"):
        before = _to_int(eda.get("metrics", {}) or {}, "total")
        after = _to_int(eda.get("metrics_after_rebalance", {}) or {}, "total")
        stages.append({"stage": "eda", "mechanism": "auto-rebalance (random downsample)",
                       "dropped": max(before - after, 0), "kind": "balance"})

    stages += [
        {"stage": "normalize", "mechanism": "synthetic source excluded",
         "dropped": _to_int(nc, "synthetic_excluded"), "kind": "policy"},
        {"stage": "normalize", "mechanism": "exact duplicate",
         "dropped": _to_int(nc, "exact_dups"), "kind": "redundancy"},
        {"stage": "normalize", "mechanism": "near duplicate",
         "dropped": _to_int(nc, "near_dups"), "kind": "fuzzy"},
        {"stage": "normalize", "mechanism": "schema rejected",
         "dropped": _to_int(nc, "rejected"), "kind": "quality"},
    ]

    # Per-source aggregation from the per-file clean report rows.
    agg: dict[tuple, dict] = {}
    for r in files:
        key = (r.get("sub_domain", ""), r.get("source", ""))
        a = agg.setdefault(key, {"sub_domain": key[0], "source": key[1],
                                 "in": 0, "out": 0,
                                 **{c: 0 for c, _ in _CLEAN_DROP_COLS}})
        a["in"] += _to_int(r, "in")
        a["out"] += _to_int(r, "out")
        for col, _lbl in _CLEAN_DROP_COLS:
            a[col] += _to_int(r, col)

    per_source: list[dict] = []
    for a in agg.values():
        top_col, top_lbl = max(_CLEAN_DROP_COLS, key=lambda cl: a.get(cl[0], 0))
        per_source.append({
            "source": a["source"], "sub_domain": a["sub_domain"],
            "in": a["in"], "out": a["out"], "lost": a["in"] - a["out"],
            "kept_pct": round(100 * a["out"] / a["in"], 1) if a["in"] else 0.0,
            "top_drop_reason": top_lbl if a.get(top_col, 0) > 0 else "-",
        })
    per_source.sort(key=lambda d: d["lost"], reverse=True)

    return {"raw_in": raw_in, "clean_out": clean_out, "final_written": final_written,
            "stages": stages, "per_source": per_source}


# -------------------------------------------------------------- stage funnels -
def sourcing_funnel() -> dict:
    """What the last sourcing run pulled back, and what it kept — a strict funnel.

    Reads the ``funnel`` block of the newest ``summary-*.json`` (written by
    :func:`cybersec_slm.sourcing.run.discover`) and turns it into display rows::

        {"ran": bool, "found": int,
         "rows": [{"stage", "detail", "count", "pct"} ...],   # the funnel, in order
         "restricted_hosts": [{"host", "count"} ...],         # legal-scope cost
         "by_domain": [{"sub-domain", "found", "dropped", "candidates", "kept_pct"}]}

    ``ran`` is False on a fresh checkout, or when the newest summary predates the
    funnel block (an older run) — the caller shows a hint rather than a table of
    zeros that looks like a run which found nothing.
    """
    summ = latest_source_summary() or {}
    f = summ.get("funnel") or {}
    if not f:
        return {"ran": False, "found": 0, "rows": [], "restricted_hosts": [],
                "by_domain": []}

    found = _to_int(f, "found")

    def pct(n: int) -> float:
        return round(100 * n / found, 1) if found else 0.0

    dropped = f.get("dropped") or {}
    lic = f.get("license") or {}
    rows = [{"stage": "search hits", "detail": "returned by SearXNG",
             "count": found, "pct": 100.0 if found else 0.0}]
    rows += [{"stage": f"dropped: {cat}",
              "detail": _DROP_DETAIL.get(cat, ""),
              "count": _to_int(dropped, cat), "pct": pct(_to_int(dropped, cat))}
             for cat in dropped]
    rows += [
        {"stage": "dropped: duplicate", "detail": "already in the catalog, or seen this run",
         "count": _to_int(f, "duplicates"), "pct": pct(_to_int(f, "duplicates"))},
        {"stage": "candidates", "detail": "survived the filters, licence resolved",
         "count": _to_int(f, "candidates"), "pct": pct(_to_int(f, "candidates"))},
        {"stage": "  licence ok", "detail": "clearly commercial -> keepable",
         "count": _to_int(lic, "ok"), "pct": pct(_to_int(lic, "ok"))},
        {"stage": "  licence unknown", "detail": "blank or unrecognised -> needs a human",
         "count": _to_int(lic, "unknown"), "pct": pct(_to_int(lic, "unknown"))},
        {"stage": "  licence blocked", "detail": "confirmed red (copyleft / NC / ARR)",
         "count": _to_int(lic, "blocked"), "pct": pct(_to_int(lic, "blocked"))},
        {"stage": "appended", "detail": "written to the catalog",
         "count": _to_int(f, "appended"), "pct": pct(_to_int(f, "appended"))},
    ]
    unprocessed = _to_int(f, "unprocessed")
    if unprocessed:
        rows.insert(-4, {
            "stage": "unprocessed",
            "detail": "fetched, but the run hit its cap/budget before examining them",
            "count": unprocessed, "pct": pct(unprocessed)})

    by_domain = []
    for dom, d in sorted((f.get("by_domain") or {}).items()):
        dfound = _to_int(d, "found")
        by_domain.append({
            "sub-domain": dom, "found": dfound, "dropped": _to_int(d, "dropped"),
            "candidates": _to_int(d, "candidates"),
            "kept_pct": (round(100 * _to_int(d, "candidates") / dfound, 1)
                         if dfound else 0.0),
        })

    hosts = [{"host": h, "count": n}
             for h, n in (f.get("restricted_by_host") or {}).items()]
    return {"ran": True, "found": found, "rows": rows,
            "restricted_hosts": hosts, "by_domain": by_domain}


# Drop category -> the one-line explanation shown next to it.
_DROP_DETAIL = {
    "bad link": "empty or host-less URL",
    "junk host": "social / video / Q&A host",
    "restricted host": "licence bars commercial reuse (see docs/sources/legal_scope.md)",
    "listing page": "a search / tag / topic page, not a single source",
}

# Ingest status -> (display label, why). Mirrors ingest_table()'s `status` values.
_INGEST_STATUS = {
    "ingested": ("ingested", "produced records under data/raw/"),
    "license": ("blocked: licence", "the commercial-licence gate turned it away"),
    "failed": ("failed", "the fetch errored"),
    "timed out": ("timed out", "the fetch exceeded its budget"),
    "rejected": ("rejected", "fetched but rejected before writing"),
    "no records": ("no records", "fetched but produced nothing usable"),
}


def ingest_funnel(rows: list[dict] | None = None) -> dict:
    """Catalog -> ingested, with every source that fell out and why.

    Aggregates :func:`ingest_table` by ``status``. ``rows`` accepts a cached
    ``ingest_table()`` result (it walks ``data/raw``); omit to compute now.
    Returns ``{"total", "ingested", "rows": [{"outcome","detail","sources","pct"}]}``
    ordered ingested-first, then by size of the loss.
    """
    rows = ingest_table() if rows is None else rows
    total = len(rows)
    by_status: dict[str, int] = {}
    for r in rows:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1

    def pct(n: int) -> float:
        return round(100 * n / total, 1) if total else 0.0

    out = []
    for status, n in by_status.items():
        label, detail = _INGEST_STATUS.get(status, (status, ""))
        out.append({"outcome": label, "detail": detail, "sources": n, "pct": pct(n)})
    out.sort(key=lambda r: (r["outcome"] != "ingested", -r["sources"]))
    return {"total": total, "ingested": by_status.get("ingested", 0), "rows": out}


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
