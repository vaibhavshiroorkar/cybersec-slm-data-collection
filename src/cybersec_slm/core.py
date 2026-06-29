#!/usr/bin/env python3
"""Shared core used by every pipeline stage — one place per purpose.

Holds what extraction and cleaning both need: an optional-dependency loader,
a single configured logger (loguru if present, else stdlib), the workspace data
paths, and line-oriented JSONL helpers + hashing.

Data paths are resolved from ``CYBERSEC_SLM_DATA_ROOT`` if set, otherwise the
current working directory — so running a command from the project root puts
``raw_data/``, ``clean_data/``, ``logs/`` etc. there, while tests can point them
elsewhere.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import sys
from collections.abc import Iterator


# ------------------------------------------------------- optional imports -----
def try_import(name: str):
    """Import a module by name, returning None if it is unavailable."""
    try:
        return importlib.import_module(name)
    except Exception:
        return None


# ------------------------------------------------------------- .env loading ---
# Load a project .env (if present) so API keys land in os.environ before any
# stage reads them. python-dotenv is optional; without it, keys must be exported
# in the shell. Existing environment variables are never overridden.
_dotenv = try_import("dotenv")
if _dotenv is not None:
    _dotenv.load_dotenv(_dotenv.find_dotenv(usecwd=True))


# ---------------------------------------------------------------- paths ------
def data_root() -> str:
    return os.environ.get("CYBERSEC_SLM_DATA_ROOT") or os.getcwd()


DATA_ROOT = data_root()
RAW_DATA = os.path.join(DATA_ROOT, "raw_data")     # extraction output / cleaning input
CLEAN_DATA = os.path.join(DATA_ROOT, "clean_data")  # streaming per-source clean output
FINAL_DATA = os.path.join(DATA_ROOT, "final_data")  # canonical release dataset + sidecars
FLAGGED = os.path.join(DATA_ROOT, "flagged")        # -> Data Annotation Team
DROPPED = os.path.join(DATA_ROOT, "dropped")        # -> audit
STAGES = os.path.join(DATA_ROOT, "_stages")         # single-stage diagnostics
LOGS = os.path.join(DATA_ROOT, "logs")


# ----------------------------------------------------------------- logging ---
def _make_logger():
    loguru = try_import("loguru")
    os.makedirs(LOGS, exist_ok=True)
    # One log file per process. With ProcessPoolExecutor under spawn (Windows),
    # every worker re-imports this module and opens its own file sink; a shared
    # path makes loguru's rotation os.rename() fail with WinError 32 because
    # other processes still hold the file open. PID-scoped paths avoid that.
    log_file = os.path.join(LOGS, f"pipeline.{os.getpid()}.log")
    if loguru is not None:
        lg = loguru.logger
        lg.remove()
        lg.add(sys.stderr, level="INFO",
               format="<green>{time:HH:mm:ss}</green> | "
                      "<level>{level:<7}</level> | {message}")
        lg.add(log_file, level="DEBUG", rotation="10 MB", enqueue=True)
        return lg
    import logging
    lg = logging.getLogger("cybersec_slm")
    lg.setLevel(logging.DEBUG)
    if not lg.handlers:
        fmt = logging.Formatter("%(asctime)s | %(levelname)-7s | %(message)s", "%H:%M:%S")
        sh = logging.StreamHandler(); sh.setLevel(logging.INFO); sh.setFormatter(fmt)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG); fh.setFormatter(fmt)
        lg.addHandler(sh); lg.addHandler(fh)
    return lg


logger = _make_logger()


# --------------------------------------------------------------- integrity ---
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------- JSONL I/O -----
PARSE_ERROR = "_parse_error"     # marker key on lines that failed to parse


def iter_jsonl(path: str) -> Iterator[dict]:
    """Yield one dict per line. Malformed lines yield {PARSE_ERROR: True, ...}
    so callers can count them instead of crashing."""
    with open(path, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                yield {PARSE_ERROR: True, "_line": n}
                continue
            yield obj if isinstance(obj, dict) else {PARSE_ERROR: True, "_line": n}


def count_lines(path: str) -> int:
    n = 0
    with open(path, "rb") as f:
        for _ in f:
            n += 1
    return n


class JsonlWriter:
    """Lazily-opened JSONL writer (no file created until the first record)."""

    def __init__(self, path: str):
        self.path = path
        self._fh = None
        self.count = 0

    def write(self, rec: dict) -> None:
        if self._fh is None:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            self._fh = open(self.path, "w", encoding="utf-8")
        self._fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.count += 1

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
