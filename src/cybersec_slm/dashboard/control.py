#!/usr/bin/env python3
"""Pipeline process control for the dashboard: start / stop / resume / reset.

The read-only dashboard gains a local control plane through this one module (no
Streamlit import, so it is unit-testable). It launches ``cybersec-slm all`` as a
detached subprocess, tracks it via a small JSON control file under the data
root's ``logs/``, can stop the whole process tree, and can wipe every pipeline
artifact for a clean slate.

Controls act on the machine running the dashboard (this is a local-first tool).
The existing live monitor (``data.run_status`` / ``live_progress`` / ``log_tail``)
reads the per-PID ``pipeline.<pid>.log`` and the resume ledger, so a started run
lights up the monitor with no extra wiring.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import time

from .. import core, stages
from . import settings_store

CONTROL_NAME = "pipeline_run.json"
PLAN_NAME = "pipeline_plan.json"

# Which advanced-settings keys each stage accepts. The dashboard offers only a
# stage's own flags; build_command drops anything else. Mirrors the CLI.
_STAGE_FLAGS: dict[str, set[str]] = {
    "all": {"workers", "sources", "source_timeout", "limit", "purge_raw",
            "resume", "no_auto_rebalance", "max_source_gb", "drop_non_english",
            "no_crawler"},
    "source": {"domains", "mode", "per_keyword", "max_per_domain", "max_total",
               "max_minutes", "workers", "time_range", "no_site_scope",
               "no_quality_filter", "dry_run", "searxng_url", "language",
               "no_enrich", "backfill", "backfill_all", "no_blacklist", "limit",
               "engines", "target_per_domain"},
    "ingest": {"workers", "sources", "source_timeout", "limit", "resume",
               "max_source_gb", "no_crawler", "domains", "sources_only",
               "no_hazard_scan"},
    "clean": {"purge_raw", "limit", "resume", "workers", "drop_non_english", "domains",
              "sources_only", "min_text_chars", "max_text_chars", "garbage_max",
              "repeat_max", "near_dup_threshold", "shingle_size", "minhash_perm",
              "allowed_langs"},
    "eda": {"no_auto_rebalance", "no_enforce", "min_total_records",
            "min_records_per_subdomain", "max_source_share", "max_drift",
            "max_dup_rate", "min_avg_tokens", "max_topic_cv",
            "min_subdomain_share", "owner"},
    "schema": {"fresh", "limit"},
}

# setting key -> (cli flag, kind). "value" flags take an argument; "bool" flags
# are bare switches emitted only when truthy; "list" flags emit the flag followed
# by each value (for nargs="*" args). Ordered so build_command output is
# deterministic (tests match exact substrings); "list" flags come last so their
# greedy nargs="*" never swallows a following flag's value.
_FLAG_SPEC: list[tuple[str, str, str]] = [
    ("workers", "--workers", "value"),
    ("sources", "--sources", "value"),
    ("source_timeout", "--source-timeout", "value"),
    ("limit", "--limit", "value"),
    ("max_source_gb", "--max-source-gb", "value"),
    ("mode", "--mode", "value"),
    ("per_keyword", "--per-keyword", "value"),
    ("max_per_domain", "--max-per-domain", "value"),
    ("max_total", "--max-total", "value"),
    ("max_minutes", "--max-minutes", "value"),
    ("target_per_domain", "--target-per-domain", "value"),
    ("engines", "--engines", "value"),
    ("time_range", "--time-range", "value"),
    ("searxng_url", "--searxng-url", "value"),
    ("language", "--language", "value"),
    ("min_text_chars", "--min-text-chars", "value"),
    ("max_text_chars", "--max-text-chars", "value"),
    ("garbage_max", "--garbage-max", "value"),
    ("repeat_max", "--repeat-max", "value"),
    ("near_dup_threshold", "--near-dup-threshold", "value"),
    ("shingle_size", "--shingle-size", "value"),
    ("minhash_perm", "--minhash-perm", "value"),
    ("min_total_records", "--min-total-records", "value"),
    ("min_records_per_subdomain", "--min-records-per-subdomain", "value"),
    ("max_source_share", "--max-source-share", "value"),
    ("max_drift", "--max-drift", "value"),
    ("max_dup_rate", "--max-dup-rate", "value"),
    ("min_avg_tokens", "--min-avg-tokens", "value"),
    ("max_topic_cv", "--max-topic-cv", "value"),
    ("min_subdomain_share", "--min-subdomain-share", "value"),
    ("owner", "--owner", "value"),
    ("purge_raw", "--purge-raw", "bool"),
    ("drop_non_english", "--drop-non-english", "bool"),
    ("no_auto_rebalance", "--no-auto-rebalance", "bool"),
    ("no_enforce", "--no-enforce", "bool"),
    ("no_crawler", "--no-crawler", "bool"),
    ("no_hazard_scan", "--no-hazard-scan", "bool"),
    ("no_enrich", "--no-enrich", "bool"),
    ("no_site_scope", "--no-site-scope", "bool"),
    ("no_quality_filter", "--no-quality-filter", "bool"),
    ("backfill", "--backfill", "bool"),
    ("backfill_all", "--backfill-all", "bool"),
    ("no_blacklist", "--no-blacklist", "bool"),
    ("dry_run", "--dry-run", "bool"),
    ("fresh", "--fresh", "bool"),
    ("resume", "--resume", "bool"),
    ("domains", "--domains", "list"),
    ("sources_only", "--sources-only", "list"),
    ("allowed_langs", "--allowed-langs", "list"),
]


def build_command(stage: str = "all", *, resume: bool = False,
                  settings: dict | None = None) -> list[str]:
    """Build the ``cybersec-slm <stage> ...`` command for a launch.

    Only the flags that ``stage`` accepts (per ``_STAGE_FLAGS``) are emitted; any
    other setting is dropped. ``resume=True`` adds ``--resume`` when the stage
    supports it. Pure and side-effect-free, so it is unit-tested directly.
    """
    merged = dict(settings or {})
    if resume:
        merged["resume"] = True
    allowed = _STAGE_FLAGS.get(stage, set())
    cmd = [sys.executable, "-m", "cybersec_slm", stage]
    for key, flag, kind in _FLAG_SPEC:
        if key not in allowed or key not in merged:
            continue
        val = merged[key]
        if kind == "bool":
            if val:
                cmd.append(flag)
        elif kind == "list":
            vals = [str(v) for v in (val or []) if str(v) != ""]
            if vals:
                cmd += [flag, *vals]
        elif val is not None and val != "":
            cmd += [flag, str(val)]
    return cmd


def stage_argv(stage: str, *, resume: bool = False,
               settings: dict | None = None) -> list[str]:
    """The CLI argv (``[stage, *flags]``) for one stage, without the interpreter.

    ``build_command`` prefixes ``python -m cybersec_slm``; this drops those three
    tokens so ``cli.main(stage_argv(...))`` can run the stage in-process (used by
    the five-stage full-run orchestrator).
    """
    return build_command(stage, resume=resume, settings=settings)[3:]


def build_full_plan(overrides: dict | None = None, *,
                    resume: bool = False) -> list[list[str]]:
    """The ordered per-stage argv list for a full ``source->...->schema`` run.

    Each stage is built from its own saved advanced settings
    (``settings_store.get_stage``) with ``overrides`` (the Overview panel) layered
    on top so a live Overview edit wins over a per-page save. ``build_command``
    drops any flag a stage does not accept, so a cross-stage key (e.g. ``domains``)
    falls away harmlessly per stage. With ``resume=True`` the ``source`` stage is
    skipped (discovery appends new rows and has no checkpoint) and ``--resume`` is
    passed to the stages that support it (ingest, clean). Pure and side-effect-free.
    """
    over = dict(overrides or {})
    plan: list[list[str]] = []
    for key in stages.stage_keys():
        if resume and key == "source":
            continue
        if over.get(f"skip_{key}"):
            continue
        effective = {**settings_store.get_stage(key), **over}
        plan.append(stage_argv(key, resume=resume, settings=effective))
    return plan


def build_quick_finish_plan(overrides: dict | None = None) -> list[list[str]]:
    """Snapshot the corpus cleaned so far, then carry on cleaning.

    Cleaning a large corpus takes days, and until it finishes there is no dataset
    to look at. This orders the same stages so there is::

        eda --no-enforce  ->  schema  ->  clean --resume  ->  eda  ->  schema

    The first eda/schema run over ``data/clean`` exactly as it stands, producing a
    real ``data/final/dataset.jsonl`` from the sources cleaned so far. Cleaning then
    resumes from its ledger — the snapshot never touches it, so nothing is
    recleaned — and a final eda/schema rebuilds the dataset over the fuller corpus.

    Two details make it safe rather than merely convenient:

    * the snapshot's eda is ``--no-enforce``. A partial corpus fails the
      sufficiency gate by construction, and an enforced failure would end the run
      before it got back to cleaning — turning "snapshot and continue" into "stop".
    * the snapshot skips ``final_global_dedup`` (that only runs at the end of a
      clean pass), but ``normalize`` does its own exact + near dedup, so the
      snapshot dataset is still deduplicated.

    Pure and side-effect-free, like the other plan builders.
    """
    over = dict(overrides or {})
    snap = {**settings_store.get_stage("eda"), **over, "no_enforce": True}
    clean = {**settings_store.get_stage("clean"), **over}
    final_eda = {**settings_store.get_stage("eda"), **over}
    schema = {**settings_store.get_stage("schema"), **over}
    return [
        stage_argv("eda", settings=snap),                  # snapshot: observe only
        stage_argv("schema", settings=schema),
        stage_argv("clean", resume=True, settings=clean),  # carry on from the ledger
        stage_argv("eda", settings=final_eda),
        stage_argv("schema", settings=schema),
    ]


def _logs_dir() -> str:
    return os.path.join(core.data_root(), "logs")


def _control_file() -> str:
    return os.path.join(_logs_dir(), CONTROL_NAME)


def _plan_file() -> str:
    return os.path.join(_logs_dir(), PLAN_NAME)


def _read_control() -> dict | None:
    try:
        with open(_control_file(), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _clear_control() -> None:
    try:
        os.remove(_control_file())
    except OSError:
        pass


def _pid_alive(pid) -> bool:
    if not pid:
        return False
    try:
        import psutil
        return psutil.pid_exists(int(pid))
    except Exception:
        try:
            os.kill(int(pid), 0)
            return True
        except (OSError, ValueError, TypeError):
            return False


def status() -> dict:
    """Current run state from the control file + PID liveness.

    ``stale`` is True when a control file exists but its process is gone (a run
    that ended without a clean Stop), which the callers treat as idle.
    """
    ctl = _read_control() or {}
    pid = ctl.get("pid")
    running = _pid_alive(pid)
    return {
        "running": running,
        "pid": pid or None,
        "stage": ctl.get("stage"),
        "started_at": ctl.get("started_at"),
        "resume": bool(ctl.get("resume", False)),
        "cmd": ctl.get("cmd"),
        "stale": bool(ctl) and not running,
    }


def _spawn_detached(cmd: list[str], *, root: str, logs: str) -> int:
    """Launch ``cmd`` detached with the dashboard's data root; return its PID.

    The child survives dashboard reruns and can be killed as a whole tree; its
    stdout/stderr go to ``logs/pipeline_control.out`` while the pipeline writes its
    own ``logs/pipeline.<pid>.log`` that the live monitor tails.
    """
    env = {**os.environ, "CYBERSEC_SLM_DATA_ROOT": root}
    out = open(os.path.join(logs, "pipeline_control.out"), "ab")
    kwargs: dict = {"cwd": root, "env": env, "stdout": out, "stderr": out,
                    "stdin": subprocess.DEVNULL}
    if os.name == "nt":
        # DETACHED_PROCESS (0x8) + new group: survive dashboard reruns, kill as a tree.
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000008
    else:
        kwargs["start_new_session"] = True
    try:
        proc = subprocess.Popen(cmd, **kwargs)
    finally:
        out.close()
    return proc.pid


def start(stage: str = "all", *, resume: bool = False,
          settings: dict | None = None, _command: list[str] | None = None) -> dict:
    """Spawn one pipeline ``stage`` (default the full ``all`` run) as a detached
    subprocess.

    Refuses when a run is already live. ``stage`` is one of ``all``, ``source``,
    ``ingest``, ``clean``, ``eda``, ``schema``. For a single stage, ``settings``
    carries the advanced flags (worker count, source-timeout, purge-raw, ...) that
    ``build_command`` filters to the ones that stage accepts. For ``all`` the child
    is the five-stage orchestrator (``run_all``) and ``settings`` is the Overview
    override layer applied on top of each page's saved settings. ``resume`` adds
    ``--resume`` where supported. ``_command`` overrides the launched command (a
    test seam; skips the plan/orchestrator branch). The child
    runs with the dashboard's data root so its output lands where the dashboard
    reads; its stdout/stderr go to ``logs/pipeline_control.out`` and the pipeline
    writes its own ``logs/pipeline.<pid>.log`` that the live monitor tails.
    """
    st = status()
    if st["running"]:
        return {"ok": False, "error": f"a run is already active (pid {st['pid']})"}

    root = core.data_root()
    logs = _logs_dir()
    os.makedirs(logs, exist_ok=True)
    if _command is not None:
        cmd = _command
    elif stage in ("all", "quick-finish"):
        # One detached orchestrator running a plan of stages in order, each with
        # its own page's saved settings (overridden by ``settings``, the Overview
        # panel). The plan is handed to it via logs/pipeline_plan.json.
        plan = (build_quick_finish_plan(settings) if stage == "quick-finish"
                else build_full_plan(settings, resume=resume))
        with open(_plan_file(), "w", encoding="utf-8") as f:
            json.dump(plan, f)
        cmd = [sys.executable, "-m", "cybersec_slm.dashboard.run_all", _plan_file()]
    else:
        cmd = build_command(stage, resume=resume, settings=settings)
    pid = _spawn_detached(cmd, root=root, logs=logs)

    ctl = {"pid": pid, "cmd": cmd, "stage": stage,
           "resume": bool(resume or (settings or {}).get("resume")),
           "started_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    with open(_control_file(), "w", encoding="utf-8") as f:
        json.dump(ctl, f)
    return {"ok": True, "pid": pid, "stage": stage, "resume": ctl["resume"]}


def _kill_tree(pid: int) -> bool:
    """Terminate a process and all its descendants; escalate to kill after 5s."""
    try:
        import psutil
        parent = psutil.Process(pid)
        procs = parent.children(recursive=True) + [parent]
        for p in procs:
            try:
                p.terminate()
            except psutil.Error:
                pass
        _gone, alive = psutil.wait_procs(procs, timeout=5)
        for p in alive:
            try:
                p.kill()
            except psutil.Error:
                pass
        return True
    except Exception:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                           capture_output=True)
        else:
            try:
                os.kill(pid, 15)
            except OSError:
                pass
        return True


def stop() -> dict:
    """Kill the running pipeline process tree and clear the control file."""
    ctl = _read_control() or {}
    pid = ctl.get("pid")
    stopped = _kill_tree(int(pid)) if _pid_alive(pid) else False
    _clear_control()
    return {"ok": True, "stopped": stopped}


def _force_rmtree(path: str) -> list[str]:
    """Delete a directory tree, clearing read-only bits; never raise.

    Returns the paths that could not be removed. ``shutil.rmtree(ignore_errors=
    True)`` silently leaves read-only files behind on Windows (so a "reset" only
    half-clears ``data/``); this clears the read-only bit and retries each failed
    entry. A file another process still holds open (e.g. the dashboard's own live
    log) genuinely cannot be deleted on Windows and is reported, not swallowed.
    """
    failed: list[str] = []

    def _onexc(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)                       # retry the delete now that it's writable
        except OSError:
            failed.append(p)

    try:
        shutil.rmtree(path, onexc=_onexc)
    except TypeError:                     # Python < 3.12: onexc unsupported
        shutil.rmtree(path, onerror=lambda f, p, _e: _onexc(f, p, None))
    except OSError:
        failed.append(path)
    return failed


def reset() -> dict:
    """Delete ALL pipeline output (``data/`` and ``logs/``) under the data root.

    Refuses while a run is active (stop it first). The ``data/`` folder is cleared
    completely (read-only files included); ``logs/`` is cleared too, except a log
    file the current process still holds open, which is reported in ``skipped``
    rather than silently left behind. The curated catalog under ``sources/`` is
    never touched. Returns ``{ok, removed, skipped}``.
    """
    if status()["running"]:
        return {"ok": False, "error": "stop the running pipeline before resetting"}
    root = core.data_root()
    removed: list[str] = []
    skipped: list[str] = []
    for sub in ("data", "logs"):
        path = os.path.join(root, sub)
        if not os.path.isdir(path):
            continue
        skipped.extend(_force_rmtree(path))
        if os.path.isdir(path):
            # A locked entry kept the tree alive (only ever the live log file);
            # data/ has no such handle, so it is always fully removed here.
            continue
        removed.append(sub)
    return {"ok": True, "removed": removed, "skipped": skipped}
