#!/usr/bin/env python3
"""Report the executables an archive shipped, rather than deleting them unseen.

Ingestion keeps only :data:`common.EXT_PRIORITY` files out of an extracted
archive. Everything else -- ``.exe``, ``.dll``, ``.so``, nested archives, Office
documents -- was dropped with no log line and no ledger entry, and then the
extraction directory was ``rmtree``'d. A repo could ship a malicious binary and
the pipeline would report nothing at all.

Note what the gap is and is not. Nothing here is ever executed: the readers parse
CSV/JSON/Parquet and a binary matches no reader. So the risk is not that the
pipeline runs it; the risk is that a corpus built from a repo carrying malware
looks, in every artifact, identical to one built from a clean repo. This module
makes the difference visible. It reports; it does not sandbox, and it does not
block -- deciding what to do about a flagged source is an operator's call.

Detection is on magic bytes, not the extension, because the extension is the
attacker's to choose: an ``innocent.csv`` that starts with ``MZ`` is exactly the
case a name-based check waves through.
"""

from __future__ import annotations

import json
import os
import time

from ..core import LOGS, logger

# One line per source that shipped a binary. A sidecar rather than a column on the
# ingest ledger: IngestLog.COLS is a fixed schema several readers depend on, and
# this is a report an operator reads occasionally, not a field of every row.
REPORT_NAME = "binary_scan.jsonl"

# Magic-byte signature -> a short label. Deliberately small: these are the shapes
# that matter for "a repo shipped an executable", not a general file-type oracle
# (that is what libmagic is for, and it is a dependency this does not need).
_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "pe"),                          # Windows PE: .exe, .dll
    (b"\x7fELF", "elf"),                    # Linux/BSD executables and .so
    (b"\xcf\xfa\xed\xfe", "macho"),         # Mach-O 64-bit LE
    (b"\xce\xfa\xed\xfe", "macho"),         # Mach-O 32-bit LE
    (b"\xca\xfe\xba\xbe", "macho"),         # Mach-O universal binary
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),   # OLE: legacy Office macros
    (b"PK\x03\x04", "zip"),                 # nested archive
    (b"\x1f\x8b", "gzip"),                  # nested archive
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\xfd7zXZ\x00", "xz"),
)

_MAX_MAGIC = max(len(sig) for sig, _ in _SIGNATURES)

# How many findings a single source reports. A repo of 10,000 binaries is one
# thing to act on, not 10,000 log lines; count_binaries still gives the true total.
DEFAULT_MAX_REPORT = 20


def sniff(path: str) -> str:
    """The file-type label for ``path``'s magic bytes, or "" when it is not one.

    Reads only the first few bytes, so it is cheap enough to run over every entry
    of a large archive.
    """
    try:
        with open(path, "rb") as f:
            head = f.read(_MAX_MAGIC)
    except OSError:
        return ""
    if not head:
        return ""
    for sig, label in _SIGNATURES:
        if head.startswith(sig):
            return label
    return ""


def _walk(root: str):
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            yield os.path.join(dirpath, name)


def scan_tree(root: str, *, max_report: int = DEFAULT_MAX_REPORT) -> list[dict]:
    """Every binary under ``root``, as ``{path, kind, size}``, capped at
    ``max_report``.

    ``path`` is relative to ``root``: the absolute extraction path is a temp
    directory that will not exist by the time anyone reads the report, whereas the
    path inside the archive is what an operator can actually go and look at.
    """
    if not os.path.isdir(root):
        return []
    out: list[dict] = []
    for full in _walk(root):
        kind = sniff(full)
        if not kind:
            continue
        try:
            size = os.path.getsize(full)
        except OSError:
            size = 0
        out.append({"path": os.path.relpath(full, root).replace(os.sep, "/"),
                    "kind": kind, "size": size})
        if len(out) >= max_report:
            break
    return out


def count_binaries(root: str) -> int:
    """How many binaries are under ``root``, uncapped.

    Separate from :func:`scan_tree` so a capped report can still state the true
    total: "20 of 4,312" is a very different fact from "20".
    """
    if not os.path.isdir(root):
        return 0
    return sum(1 for full in _walk(root) if sniff(full))


def report_path() -> str:
    """Where the findings are appended (``logs/binary_scan.jsonl``)."""
    return os.path.join(LOGS, REPORT_NAME)


def report(root: str, *, source: str, url: str = "", domain: str = "") -> dict | None:
    """Scan ``root`` and record what it found. Returns the entry, or None if clean.

    Best-effort by contract: a source that ships a binary is worth knowing about,
    but failing to write the note is not worth failing the fetch over, so every
    error here is swallowed and logged.
    """
    try:
        found = scan_tree(root)
        if not found:
            return None
        total = count_binaries(root)
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "source": source,
            "domain": domain,
            "url": url,
            "total": total,
            "shown": len(found),
            "by_kind": _by_kind(root),
            "findings": found,
        }
        kinds = ", ".join(f"{k}x{n}" for k, n in sorted(entry["by_kind"].items()))
        logger.warning(
            f"  binary scan: {source} ships {total} non-data binary file(s) "
            f"({kinds}); they are reported, not ingested and never executed. "
            f"See logs/{REPORT_NAME}")
        os.makedirs(LOGS, exist_ok=True)
        with open(report_path(), "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        return entry
    except Exception as e:                       # noqa: BLE001 - best-effort
        logger.debug(f"binscan: {source}: {type(e).__name__}: {e}")
        return None


def _by_kind(root: str) -> dict[str, int]:
    """Count of every binary under ``root`` by kind, uncapped."""
    out: dict[str, int] = {}
    for full in _walk(root):
        kind = sniff(full)
        if kind:
            out[kind] = out.get(kind, 0) + 1
    return out


def findings(path: str | None = None) -> list[dict]:
    """Every recorded finding, newest last. Empty when nothing has been scanned."""
    p = path or report_path()
    if not os.path.exists(p):
        return []
    out: list[dict] = []
    try:
        with open(p, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        continue
    except OSError:
        return []
    return out
