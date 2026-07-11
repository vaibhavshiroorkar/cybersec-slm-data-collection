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
        "started_at": ctl.get("started_at"),
        "resume": bool(ctl.get("resume", False)),
        "cmd": ctl.get("cmd"),
        "stale": bool(ctl) and not running,
    }


def start(resume: bool = False, *, _command: list[str] | None = None) -> dict:
    """Spawn the full pipeline (``cybersec-slm all``) as a detached subprocess.

    Refuses when a run is already live. ``resume`` adds ``--resume`` so the run
    skips sources already completed (``logs/completed_sources.txt``). ``_command``
    overrides the launched command (a test seam). The child runs with the
    dashboard's data root so its output lands where the dashboard reads; its
    stdout/stderr go to ``logs/pipeline_control.out`` and the pipeline writes its
    own ``logs/pipeline.<pid>.log`` that the live monitor tails.
    """
    st = status()
    if st["running"]:
        return {"ok": False, "error": f"a run is already active (pid {st['pid']})"}

    root = core.data_root()
    logs = _logs_dir()
    os.makedirs(logs, exist_ok=True)
    cmd = _command or ([sys.executable, "-m", "cybersec_slm", "all"]
                       + (["--resume"] if resume else []))
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

    ctl = {"pid": proc.pid, "cmd": cmd, "resume": bool(resume),
           "started_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    with open(_control_file(), "w", encoding="utf-8") as f:
        json.dump(ctl, f)
    return {"ok": True, "pid": proc.pid, "resume": bool(resume)}


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
