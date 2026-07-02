#!/usr/bin/env python3
"""Launch the Streamlit dashboard as a subprocess (the `cybersec-slm dashboard` CLI).

Kept out of ``cli.py`` so the CLI import stays free of any Streamlit assumption:
this only shells out when the command actually runs, and degrades with a helpful
message when the optional ``dashboard`` extra isn't installed.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys

from ..core import logger


def _skip_first_run_prompt() -> None:
    """Pre-create Streamlit's credentials file so its first-launch email prompt
    never blocks on stdin (Streamlit writes this itself once you answer it)."""
    cfg = os.path.join(os.path.expanduser("~"), ".streamlit", "credentials.toml")
    if os.path.exists(cfg):
        return
    try:
        os.makedirs(os.path.dirname(cfg), exist_ok=True)
        with open(cfg, "w", encoding="utf-8") as f:
            f.write('[general]\nemail = ""\n')
    except OSError:
        pass


def launch(port: int = 8501, headless: bool = False) -> int:
    """Run ``streamlit run app.py``. Returns the subprocess exit code (0 on the
    graceful 'not installed' path so the CLI doesn't look like it crashed)."""
    if importlib.util.find_spec("streamlit") is None:
        print("dashboard: Streamlit is not installed. Install the optional extra:\n"
              "    uv sync --extra dashboard\n"
              "then re-run:  cybersec-slm dashboard")
        return 0
    _skip_first_run_prompt()
    app = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.py")
    cmd = [sys.executable, "-m", "streamlit", "run", app, "--server.port", str(port)]
    if headless:
        cmd += ["--server.headless", "true"]
    env = {**os.environ, "STREAMLIT_BROWSER_GATHER_USAGE_STATS": "false"}
    logger.info(f"dashboard: launching Streamlit on :{port} -> {app}")
    return subprocess.run(cmd, env=env).returncode
