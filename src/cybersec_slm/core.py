#!/usr/bin/env python3
"""Shared core used by every pipeline stage: one place per purpose.

Holds what ingestion and cleaning both need: an optional-dependency loader,
a single configured logger (loguru if present, else stdlib), the workspace data
paths, and line-oriented JSONL helpers + hashing.

Data paths are resolved from ``CYBERSEC_SLM_DATA_ROOT`` if set, otherwise the
current working directory. Every generated corpus artifact lives under a single
``data/`` folder (``data/raw``, ``data/clean``, ``data/final`` …) so the project
root stays uncluttered; ``logs/`` sits alongside it. Tests can point the root
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
#
# Resolve the .env deterministically: first search up from the current working
# directory (find_dotenv), then fall back to the repo root derived from this
# file's location. The fallback matters because the dashboard is often launched
# from a different working directory (e.g. by Streamlit), where a cwd-only search
# would silently find nothing and every API key would look "unset".
_dotenv = try_import("dotenv")
if _dotenv is not None:
    _repo_env = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        ".env")
    _env_path = _dotenv.find_dotenv(usecwd=True) or (
        _repo_env if os.path.exists(_repo_env) else "")
    if _env_path:
        _dotenv.load_dotenv(_env_path)


# ---------------------------------------------------------------- paths ------
# The profile whose corpus is built when nothing says otherwise. Defined here, not
# in sourcing.taxonomies, because this module must resolve a profile without
# importing anything from the package: taxonomies and profiles both import core,
# so core importing them back would be a cycle, and a fatal one -- _make_logger()
# runs at import (below) and needs LOGS, which needs the profile.
DEFAULT_PROFILE = "ubi"

# The profiles that ship built in, so a name can be validated without importing
# sourcing.taxonomies (which would be a cycle). Duplicated on purpose and pinned
# by tests/test_core.py, which asserts this agrees with taxonomies: two places
# disagreeing about which profiles exist is worse than the duplication.
BUILTIN_PROFILES = ("cybersec", "ubi")

# The old, profile-less layout, kept only to recognise a corpus that predates
# per-profile paths so it can be moved (see migrate_layout).
_LEGACY_DIRS = ("raw", "clean", "final", "flagged", "dropped", "_stages")


def data_root() -> str:
    return os.environ.get("CYBERSEC_SLM_DATA_ROOT") or os.getcwd()


def _profile_exists(name: str, root: str) -> bool:
    return (name in BUILTIN_PROFILES
            or os.path.isdir(os.path.join(root, "sources", "profiles", name)))


def active_profile(root: str | None = None) -> str:
    """The profile in force: env, else ``sources/active_profile``, else the default.

    Deliberately stdlib-only, for the import-cycle reason above;
    :func:`sourcing.profiles.active` delegates here so there is one answer to
    "which profile am I" rather than two that can disagree. Precedence matches
    what profiles documented: the env var is for a one-off run or a test and
    outranks what is persisted on disk.

    A name that does not resolve to a real profile falls back to the default, so a
    stale pointer or a typo degrades to a working pipeline instead of quietly
    building a corpus under a directory nobody meant.
    """
    root = root or data_root()
    env = (os.environ.get("CYBERSEC_SLM_PROFILE") or "").strip()
    if env and _profile_exists(env, root):
        return env
    try:
        with open(os.path.join(root, "sources", "active_profile"),
                  encoding="utf-8") as f:
            name = f.read().strip()
        if name and _profile_exists(name, root):
            return name
    except OSError:
        pass
    return DEFAULT_PROFILE


def data_dir(root: str | None = None, profile: str | None = None) -> str:
    """``<root>/data/<profile>`` -- this profile's corpus, and no other's.

    A function, not a constant, because the dashboard is one long-lived process
    that has to notice a profile switch. The constants below are the frozen
    snapshot for a pipeline *stage*, which runs in its own short-lived process.
    """
    root = root or data_root()
    return os.path.join(root, "data", profile or active_profile(root))


def logs_dir(root: str | None = None, profile: str | None = None) -> str:
    """``<root>/logs/<profile>``. Same reasoning as :func:`data_dir`."""
    root = root or data_root()
    return os.path.join(root, "logs", profile or active_profile(root))


def migrate_layout(root: str | None = None, profile: str | None = None) -> list[str]:
    """Move a pre-profile ``data/`` and ``logs/`` under ``profile``. Returns what moved.

    Before profiles owned their own corpora, everything lived at ``<root>/data`` and
    ``<root>/logs``, shared: switching to ``ubi`` showed cybersec's 1.9M records,
    its EDA report and its manifest, and a ``ubi`` run wrote into the same tree.

    Two renames per tree rather than a copy, so a 100GB corpus moves instantly on
    the same volume::

        data -> data.migrating ; mkdir data ; data.migrating -> data/<profile>

    Called from process entry points (the CLI, the dashboard), never at import: a
    ProcessPoolExecutor worker re-imports this module, and several processes racing
    to rename the same tree is precisely the way to lose it. Idempotent: once moved,
    the legacy directories are gone and this is a no-op.
    """
    root = root or data_root()
    profile = profile or active_profile(root)
    moved: list[str] = []
    for kind in ("data", "logs"):
        base = os.path.join(root, kind)
        if not os.path.isdir(base):
            continue
        legacy = (any(os.path.isdir(os.path.join(base, d)) for d in _LEGACY_DIRS)
                  if kind == "data"
                  else any(os.path.isfile(os.path.join(base, f))
                           or os.path.isdir(os.path.join(base, f))
                           for f in ("eda", "clean_report.csv", "ingest_log.sqlite",
                                     "pipeline_run.json", "discovered")))
        # An *empty* profile directory does not mean "already migrated": importing
        # this module creates logs/<profile> before anything has run (_make_logger
        # does os.makedirs(LOGS) at import). Treating that stub as done left the
        # real logs stranded at the top level, visible to no profile.
        dest = os.path.join(base, profile)
        already = os.path.isdir(dest) and bool(os.listdir(dest))
        if not legacy or already:
            continue
        if os.path.isdir(dest):
            # The empty stub, removed before the move rather than after: the whole
            # of `base` is about to become `base/<profile>`, so a stub left inside
            # would resurface as base/<profile>/<profile>.
            os.rmdir(dest)
        tmp = base + ".migrating"
        os.rename(base, tmp)                 # fails loudly if a run holds a handle
        os.makedirs(base, exist_ok=True)
        os.rename(tmp, dest)
        moved.append(kind)
    return moved


DATA_ROOT = data_root()
# Frozen at import, and that is correct for a pipeline stage: it runs in its own
# process, against one profile, for its lifetime. The dashboard must NOT read
# these -- it outlives a profile switch -- and goes through data_dir()/logs_dir().
_PROFILE = active_profile(DATA_ROOT)
DATA_DIR = data_dir(DATA_ROOT, _PROFILE)            # this profile's artifacts
RAW_DATA = os.path.join(DATA_DIR, "raw")            # ingestion output / cleaning input
CLEAN_DATA = os.path.join(DATA_DIR, "clean")        # streaming per-source clean output
FINAL_DATA = os.path.join(DATA_DIR, "final")        # canonical release dataset + sidecars
FLAGGED = os.path.join(DATA_DIR, "flagged")         # -> Data Annotation Team
DROPPED = os.path.join(DATA_DIR, "dropped")         # -> audit
STAGES = os.path.join(DATA_DIR, "_stages")          # single-stage diagnostics
LOGS = logs_dir(DATA_ROOT, _PROFILE)                # operational logs (alongside data/)

# Absolute path of this process's pipeline log file (set by _make_logger). The
# dashboard reads it to follow the actual run's log: a run's pid can differ from
# the launched pid (Windows launcher shims) and parallel workers spawn their own
# per-pid logs, so neither the control pid nor newest-by-mtime reliably identifies it.
LOG_FILE: str | None = None


# ----------------------------------------------------------------- logging ---
def _make_logger():
    global LOG_FILE
    loguru = try_import("loguru")
    os.makedirs(LOGS, exist_ok=True)
    # One log file per process. With ProcessPoolExecutor under spawn (Windows),
    # every worker re-imports this module and opens its own file sink; a shared
    # path makes loguru's rotation os.rename() fail with WinError 32 because
    # other processes still hold the file open. PID-scoped paths avoid that.
    log_file = os.path.join(LOGS, f"pipeline.{os.getpid()}.log")
    LOG_FILE = log_file
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

# orjson is a base dependency and parses/serializes JSON several times faster
# than the stdlib; every stage funnels through these helpers, so the speedup is
# corpus-wide. Both helpers fall back to stdlib json so semantics never change:
# orjson rejects a few things stdlib accepts (NaN/Infinity literals on read,
# >64-bit ints on write) and those cases retry through stdlib.
_orjson = try_import("orjson")


def json_loads(line: str):
    """Parse one JSON document (orjson fast path, stdlib fallback)."""
    if _orjson is not None:
        try:
            return _orjson.loads(line)
        except ValueError:
            pass                 # stricter than stdlib (e.g. NaN literal) -> retry
    return json.loads(line)


def json_dumps(obj) -> str:
    """Serialize one record to a compact JSON string (non-ASCII kept raw)."""
    if _orjson is not None:
        try:
            return _orjson.dumps(obj).decode("utf-8")
        except TypeError:        # exotic type / >64-bit int -> stdlib handles
            pass
    return json.dumps(obj, ensure_ascii=False)


def iter_jsonl(path: str) -> Iterator[dict]:
    """Yield one dict per line. Malformed lines yield {PARSE_ERROR: True, ...}
    so callers can count them instead of crashing."""
    with open(path, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json_loads(line)
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
        self._fh.write(json_dumps(rec) + "\n")
        self.count += 1

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
