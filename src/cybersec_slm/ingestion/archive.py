#!/usr/bin/env python3
"""Extract a downloaded archive without letting it decide how much disk to use.

``ZipFile.extractall`` does what the archive says: an 8KB file that declares
80GB of members gets 80GB written, and the only limit is the volume. Ingestion
downloads archives from the public internet, so the archive is attacker-supplied
input and its declared sizes are a claim, not a fact.

The checks run against the central directory *before* any byte is written, which
is the point: refusing a bomb after extracting it is not refusing it. A zip's
directory carries each entry's uncompressed size, so the total is known up front.

Three limits, because one is not enough:
    * total uncompressed bytes -- the direct cap on damage.
    * entry count -- 4 billion empty files exhausts inodes without any bytes.
    * compression ratio -- catches a bomb tuned to sit just under the byte cap
      while still being obviously not a corpus.

Traversal (``../x``, ``/etc/passwd``) is refused rather than sanitised. CPython's
own ``extractall`` strips those, but this module writes entries itself, so it
owes the guarantee rather than inheriting it.
"""

from __future__ import annotations

import os
import zipfile

from ..core import logger

# Defaults sized for a corpus source, not for a filesystem. The largest genuine
# sources here are a few GB compressed; anything claiming to expand past this is
# not a dataset. Env-overridable for the rare legitimate monster.
DEFAULT_MAX_TOTAL_BYTES = 20 * 1024 * 1024 * 1024      # 20 GB uncompressed
DEFAULT_MAX_ENTRIES = 200_000
DEFAULT_MAX_RATIO = 200          # uncompressed / compressed


class UnsafeArchive(RuntimeError):
    """Raised when an archive must not be extracted."""


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, TypeError, ValueError):
        return default


def _unsafe_path(name: str) -> bool:
    """True when an entry name would write outside the destination directory."""
    if name.startswith("/") or name.startswith("\\"):
        return True
    if os.path.isabs(name) or (len(name) > 1 and name[1] == ":"):
        return True          # C:\... on Windows
    parts = name.replace("\\", "/").split("/")
    return ".." in parts


def safe_extract(src: str, dest: str, *,
                 max_total_bytes: int | None = None,
                 max_entries: int | None = None,
                 max_ratio: int | None = None) -> list[str]:
    """Extract ``src`` into ``dest``; return the paths written.

    Raises :class:`UnsafeArchive` when the archive declares more than the limits
    allow, names an entry outside ``dest``, or cannot be read as a zip. Nothing is
    written when it raises.
    """
    max_total_bytes = (max_total_bytes if max_total_bytes is not None
                       else _env_int("CYBERSEC_SLM_MAX_UNZIP_BYTES",
                                     DEFAULT_MAX_TOTAL_BYTES))
    max_entries = (max_entries if max_entries is not None
                   else _env_int("CYBERSEC_SLM_MAX_ZIP_ENTRIES",
                                 DEFAULT_MAX_ENTRIES))
    max_ratio = (max_ratio if max_ratio is not None
                 else _env_int("CYBERSEC_SLM_MAX_ZIP_RATIO", DEFAULT_MAX_RATIO))

    try:
        zf = zipfile.ZipFile(src)
    except (zipfile.BadZipFile, OSError) as e:
        raise UnsafeArchive(f"{os.path.basename(src)}: not a readable zip ({e})") from e

    with zf:
        try:
            infos = zf.infolist()
        except (zipfile.BadZipFile, OSError) as e:
            raise UnsafeArchive(
                f"{os.path.basename(src)}: unreadable zip directory ({e})") from e

        if len(infos) > max_entries:
            raise UnsafeArchive(
                f"{os.path.basename(src)}: {len(infos):,} entries exceeds the "
                f"limit of {max_entries:,}")

        total = sum(i.file_size for i in infos)
        if total > max_total_bytes:
            raise UnsafeArchive(
                f"{os.path.basename(src)}: declares {total / 1048576:,.0f} MB "
                f"uncompressed, over the {max_total_bytes / 1048576:,.0f} MB limit")

        packed = sum(i.compress_size for i in infos)
        if packed > 0 and total / packed > max_ratio:
            raise UnsafeArchive(
                f"{os.path.basename(src)}: compression ratio "
                f"{total / packed:,.0f}:1 exceeds {max_ratio}:1; refusing it as a "
                f"decompression bomb")

        for i in infos:
            if _unsafe_path(i.filename):
                raise UnsafeArchive(
                    f"{os.path.basename(src)}: entry {i.filename!r} would write "
                    f"outside the destination (path traversal)")

        written: list[str] = []
        for i in infos:
            if i.is_dir():
                continue
            out = zf.extract(i, dest)
            written.append(out)

    logger.debug(f"archive: extracted {len(written)} entries "
                 f"({total / 1048576:,.1f} MB) from {os.path.basename(src)}")
    return written
