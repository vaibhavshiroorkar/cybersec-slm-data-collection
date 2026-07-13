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
    paths = [p for p in glob.glob(os.path.join(_logs(), "pipeline.*.log"))
             if os.path.exists(p) and os.path.getsize(p) > 0]
    return sorted(paths, key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0)


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
    logs = _pipeline_logs()
    newest = logs[-1] if logs else None
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
    path = os.path.join(_repo_root(), "sources", "Sources.csv")
    rows = _read_csv(path)
    return len(rows) if rows else None


def _catalog_path() -> str:
    return os.path.join(_repo_root(), "sources", "Sources.csv")


def catalog_path() -> str:
    """Path to the source catalog CSV the dashboard reads and edits."""
    return _catalog_path()


def catalog_rows() -> list[dict]:
    """Every row of the source catalog (``sources/Sources.csv``), as read."""
    return _read_csv(_catalog_path())


def catalog_summary() -> dict:
    """Source catalog overview: total rows + per-Sub-Domain counts.

    Read straight from ``sources/Sources.csv`` so the landing page has a
    meaningful distribution to show even before any run has produced a manifest.
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


def raw_subdomains() -> list[str]:
    """Sorted Sub-Domains that have fetched data under ``data/raw/`` (for clean)."""
    raw = os.path.join(_root(), "data", "raw")
    if not os.path.isdir(raw):
        return []
    try:
        return sorted(d.name for d in os.scandir(raw) if d.is_dir())
    except OSError:
        return []


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
    is how many produced a folder under ``data/raw/``. ``total`` is the catalog
    size. So "184 checked, 149 with data, of 192" reads correctly: nearly every
    source was tried; not all yielded a downloadable corpus. Falls back to the
    on-disk folder count when the ledger is absent.
    """
    with_data = _count_source_dirs(os.path.join(_root(), "data", "raw"))
    checked = _completed_count() or with_data
    total = _catalog_total() or 0
    return {"checked": checked, "with_data": with_data, "total": total}


def raw_table() -> list[dict]:
    """Per-source rows for what is physically under ``data/raw/`` (file count + size).

    One row per ``<sub-domain>/<source>`` folder, so the table maps the folder
    tree exactly. Walks the whole raw tree once (100+ GB, so callers should cache
    it), reporting on-disk bytes rather than catalog figures. Record counts are
    omitted here because counting them means reading every JSONL line (minutes).
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
                files, total = 0, 0
                for r, _, fs in os.walk(src.path):
                    for f in fs:
                        try:
                            total += os.path.getsize(os.path.join(r, f))
                            files += 1
                        except OSError:
                            pass
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

    # Log next: fetch failures and timeouts carry the clearest reasons.
    summary: dict | None = None
    logs = _pipeline_logs()
    if logs:
        try:
            with open(logs[-1], encoding="utf-8", errors="replace") as f:
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


def sources_without_data() -> list[dict]:
    """Every catalogued source that produced no records, each with the reason.

    Reconciles the full catalog against ``data/raw/``: a source with a JSONL file
    on disk produced data and is skipped; the rest are reported. Reasons come from
    the commercial-license gate (the common case: non-commercial / copyleft /
    unrecognised licenses are turned away before download) and, for sources that
    were fetched but yielded nothing, the latest run's failure log. Each row is
    ``{"sub-domain", "source", "type", "reason"}`` where ``type`` is ``license``,
    ``failed``, ``timed out``, ``rejected``, or ``no records``.
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
    fails = {i["source"]: i for i in ingest_outcome().get("issues", [])}
    out: list[dict] = []
    for d in descs:
        dom, base = d.get("domain", ""), _descriptor_base(d)
        if _folder_has_jsonl(os.path.join(raw_root, dom, base)):
            continue
        licok, lreason = is_license_ok(d)
        if not licok:
            out.append({"sub-domain": dom, "source": base,
                        "type": "license", "reason": lreason})
            continue
        key = d.get("slug") or (d.get("ref") or "").split("/")[-1] or base
        hit = fails.get(key) or fails.get(base)
        if hit:
            out.append({"sub-domain": dom, "source": base,
                        "type": hit["kind"], "reason": hit["reason"]})
        else:
            out.append({"sub-domain": dom, "source": base, "type": "no records",
                        "reason": "fetched but produced no records (failed, timed out, or empty)"})
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
    from the dashboard); falls back to the first timestamp of the newest pipeline
    log (a CLI run has no control file). Returns None when neither is available.
    """
    from . import control
    ts = _parse_log_ts((control.status() or {}).get("started_at") or "")
    if ts is not None:
        return ts
    logs = _pipeline_logs()
    if not logs:
        return None
    try:
        with open(logs[-1], encoding="utf-8", errors="replace") as f:
            first = f.readline()
    except OSError:
        return None
    return _parse_log_ts(first.split("|", 1)[0] if "|" in first else first)


def run_timing() -> dict:
    """Elapsed time since the run started, plus a rough linear ETA.

    Returns ``{"elapsed_s", "eta_s", "basis"}``. ``elapsed_s`` is seconds since the
    run's start (None if no start time is known). ``eta_s`` is a *rough* linear
    projection (``elapsed / completed * (total - completed)``) computed only
    during the ingest phase, which is ~80% of wall-clock and the only stage driven
    by source count. Once ingestion is done the tail (dedup -> EDA -> normalize) is
    not source-count driven, so ``eta_s`` is None and ``basis`` says ``finalizing``
    rather than faking a number. Sources vary hugely in size, so treat the ETA as
    an estimate only.
    """
    start = _run_started_at()
    elapsed_s = (time.time() - start) if start is not None else None
    pkey = (run_phase() or {}).get("phase")
    completed, total = _completed_count(), _catalog_total()

    eta_s: float | None = None
    if elapsed_s is None:
        basis = "no-start"
    elif pkey == "gate_failed":
        basis = "finished"
    elif pkey == "ingest" and total and completed:
        eta_s = max(elapsed_s / completed * (total - completed), 0.0)
        basis = "ingest-linear"
    elif pkey in ("clean", "eda", "schema"):
        basis = "finalizing"
    else:
        basis = "starting"
    return {"elapsed_s": elapsed_s, "eta_s": eta_s, "basis": basis}


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


def _count_jsonl_records(path: str) -> int:
    """Count non-empty JSONL records under a directory tree."""
    if not os.path.exists(path):
        return 0
    count = 0
    try:
        for root, _, files in os.walk(path):
            for name in files:
                if name.endswith(".jsonl"):
                    file_path = os.path.join(root, name)
                    try:
                        with open(file_path, encoding="utf-8", errors="replace") as f:
                            count += sum(1 for ln in f if ln.strip())
                    except OSError:
                        pass
    except OSError:
        pass
    return count


def _count_source_dirs(path: str) -> int:
    """Count distinct source folders (domain/<source>/) that exist under path."""
    if not os.path.exists(path):
        return 0
    count = 0
    try:
        for domain_entry in os.scandir(path):
            if not domain_entry.is_dir() or domain_entry.name.startswith("."):
                continue
            for src_entry in os.scandir(domain_entry.path):
                if src_entry.is_dir() and not src_entry.name.startswith("."):
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


def data_funnel() -> dict:
    """Aggregate Raw -> Cleaned -> Final metrics for the Overview funnel.

    Source counts and sizes come from what is physically on disk under the data
    root (the honest per-machine state); raw line/size totals come from the
    catalog, which is authoritative and fast (a live count of the raw tree would
    read 100+ GB). Cleaned and final counts are read directly since those trees
    are small.
    """
    man = manifest()
    rc = clean_report()
    nr = normalize_report()
    cat = catalog_totals()

    # Raw: count the source folders present (cumulative across runs); take the
    # line/size totals from the catalog, but only claim them once raw exists.
    raw_root = os.path.join(_root(), "data", "raw")
    raw_sources = _count_source_dirs(raw_root)
    raw_lines = cat["raw_lines"] if raw_sources else 0
    raw_size_mb = cat["raw_size_mb"] if raw_sources else 0.0

    # Cleaned: prefer the clean report total when available, otherwise count the
    # actual JSONL records present under data/clean/ so the UI remains informative.
    clean_root = os.path.join(_root(), "data", "clean")
    cleaned_size_mb = _dir_size_mb(clean_root)
    cleaned_sources = _count_source_dirs(clean_root)
    cleaned_lines = int(rc.get("total", {}).get("out", 0)) if rc.get("total") else 0
    if cleaned_lines == 0:
        cleaned_lines = _count_jsonl_records(clean_root)

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
