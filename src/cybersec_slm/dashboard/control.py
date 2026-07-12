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
import subprocess
import sys
import time

from .. import core

CONTROL_NAME = "pipeline_run.json"

# Which advanced-settings keys each stage accepts. The dashboard offers only a
# stage's own flags; build_command drops anything else. Mirrors the CLI.
_STAGE_FLAGS: dict[str, set[str]] = {
    "all": {"workers", "sources", "source_timeout", "limit", "purge_raw",
            "resume", "no_auto_rebalance", "max_source_gb", "drop_non_english"},
    "source": set(),
    "ingest": {"workers", "sources", "source_timeout", "limit", "resume",
               "max_source_gb"},
    "clean": {"purge_raw", "limit", "resume", "drop_non_english"},
    "eda": {"no_auto_rebalance", "no_enforce"},
    "schema": {"fresh", "limit"},
}

# setting key -> (cli flag, kind). "value" flags take an argument; "bool" flags
# are bare switches emitted only when truthy. Ordered so build_command output is
# deterministic (tests match exact substrings).
_FLAG_SPEC: list[tuple[str, str, str]] = [
    ("workers", "--workers", "value"),
    ("sources", "--sources", "value"),
    ("source_timeout", "--source-timeout", "value"),
    ("limit", "--limit", "value"),
    ("max_source_gb", "--max-source-gb", "value"),
    ("purge_raw", "--purge-raw", "bool"),
    ("drop_non_english", "--drop-non-english", "bool"),
    ("no_auto_rebalance", "--no-auto-rebalance", "bool"),
    ("no_enforce", "--no-enforce", "bool"),
    ("fresh", "--fresh", "bool"),
    ("resume", "--resume", "bool"),
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
        elif val is not None and val != "":
            cmd += [flag, str(val)]
    return cmd


def _logs_dir() -> str:
    return os.path.join(core.data_root(), "logs")


def _control_file() -> str:
    return os.path.join(_logs_dir(), CONTROL_NAME)


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


def start(stage: str = "all", *, resume: bool = False,
          settings: dict | None = None, _command: list[str] | None = None) -> dict:
    """Spawn one pipeline ``stage`` (default the full ``all`` run) as a detached
    subprocess.

    Refuses when a run is already live. ``stage`` is one of ``all``, ``source``,
    ``ingest``, ``clean``, ``eda``, ``schema``; ``settings`` carries the advanced
    flags (worker count, source-timeout, purge-raw, ...) that ``build_command``
    filters to the ones that stage accepts. ``resume`` adds ``--resume`` where
    supported. ``_command`` overrides the launched command (a test seam). The child
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
    cmd = _command or build_command(stage, resume=resume, settings=settings)
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

    ctl = {"pid": proc.pid, "cmd": cmd, "stage": stage,
           "resume": bool(resume or (settings or {}).get("resume")),
           "started_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    with open(_control_file(), "w", encoding="utf-8") as f:
        json.dump(ctl, f)
    return {"ok": True, "pid": proc.pid, "stage": stage, "resume": ctl["resume"]}


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


def reset() -> dict:
    """Delete ALL pipeline output (``data/`` and ``logs/``) under the data root.

    Refuses while a run is active (stop it first). Returns the removed subtrees.
    This is a clean slate: raw, cleaned, final, dropped data and every run log,
    report, and the resume ledger are removed.
    """
    if status()["running"]:
        return {"ok": False, "error": "stop the running pipeline before resetting"}
    root = core.data_root()
    removed = []
    for sub in ("data", "logs"):
        path = os.path.join(root, sub)
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
            if not os.path.isdir(path):
                removed.append(sub)
    return {"ok": True, "removed": removed}
