#!/usr/bin/env python3
"""Extraction-stage helpers — HTTP, robust readers, and the ingest log.

Shared concerns (logger, try_import, sha256, count_lines, paths) live in
``cybersec_slm.core``; this module adds what only extraction needs.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time

import pandas as pd

from ..core import (LOGS, RAW_DATA, count_lines, logger, sha256_file,  # noqa: F401
                    try_import)

# ---------------------------------------------------------------- config -----
CAP_BYTES = 5 * 1024 ** 3            # 5 GB hard cap (download + jsonl)
ONE_MB = 1024 * 1024
HEADERS = {"User-Agent": "Mozilla/5.0 (corpus-pipeline)"}
DB_PATH = os.path.join(LOGS, "ingest_log.sqlite")

# Category = the TYPE of source (not major/minor).
SOURCE_CATEGORY = {
    "hf": "Dataset", "kaggle": "Dataset", "url": "Dataset",
    "github": "Repo", "pdf": "Document", "feed": "Feed", "website": "Website",
}


def category_of(kind: str) -> str:
    return SOURCE_CATEGORY.get(kind, kind.title())


# License shorthands reused across sources.
GOV_US = "Public Domain (U.S. Government work, 17 U.S.C. 105)"
GOV_IN = "Government of India (official gazette / open publication)"
MITRE = "Apache-2.0 / MITRE ATT&CK Terms (free use w/ attribution)"

# ------------------------------------------------------------- http / io -----
import httpx  # noqa: E402
from tenacity import (retry, retry_if_exception_type, stop_after_attempt,  # noqa: E402
                      wait_exponential)

_RETRY = dict(stop=stop_after_attempt(4),
              wait=wait_exponential(multiplier=1, min=2, max=30),
              retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException)),
              reraise=True)


@retry(**_RETRY)
def http_get(url: str, timeout: int = 180) -> httpx.Response:
    r = httpx.get(url, headers=HEADERS, follow_redirects=True, timeout=timeout)
    r.raise_for_status()
    return r


def remote_size(url: str) -> int | None:
    """Best-effort content-length via HEAD (None if unknown)."""
    try:
        r = httpx.head(url, headers=HEADERS, follow_redirects=True, timeout=30)
        cl = r.headers.get("content-length")
        return int(cl) if cl else None
    except Exception:
        return None


class OversizeError(Exception):
    """Raised when a file is over the 5 GB cap."""


@retry(**_RETRY)
def download(url: str, dest: str) -> tuple[int, str]:
    """Stream a URL to disk; return (bytes, sha256). Aborts past CAP_BYTES."""
    import hashlib
    h = hashlib.sha256()
    size = 0
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    with httpx.stream("GET", url, headers=HEADERS, follow_redirects=True, timeout=180) as r:
        r.raise_for_status()
        with open(dest, "wb") as f:
            for chunk in r.iter_bytes(1 << 16):
                size += len(chunk)
                if size > CAP_BYTES:
                    f.close(); os.remove(dest)
                    raise OversizeError(f"exceeds 5 GB cap ({size/1024**3:.1f} GB+)")
                f.write(chunk); h.update(chunk)
    return size, h.hexdigest()


# --------------------------------------------------------------- readers -----
NSLKDD_COLS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "class", "difficulty_level",
]
EXT_PRIORITY = (".parquet", ".jsonl", ".csv", ".json", ".xlsx",
                ".yar", ".yara", ".yml", ".yaml", ".md", ".txt")
# Rule / markup / doc files read as a single text record each (one file -> one
# record). Recovers detection rules (YARA/Sigma) and prose docs (Markdown) that
# would otherwise be dropped as having no recognized data column.
TEXT_FILE_EXTS = (".yar", ".yara", ".yml", ".yaml", ".rule", ".sigma", ".md")
SKIP_SUBSTRINGS = ("embedding", "faiss", "statistics", "data_stats", "_stats")


def _read_json_repair(path: str) -> pd.DataFrame:
    """Parse JSON tolerantly (handles hand-edited / broken JSON)."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        from json_repair import repair_json
        data = json.loads(repair_json(text))
    if isinstance(data, dict):
        data = data.get("data", data) if "data" in data else data
    if isinstance(data, list):
        # Coerce non-dict elements (scalars / nested lists) into records so
        # pandas never chokes on a mixed list — DataFrame(list) requires every
        # element to be a dict, else it raises "dictionary update sequence...".
        rows = [d if isinstance(d, dict)
                else {"text": d if isinstance(d, str)
                      else json.dumps(d, ensure_ascii=False)}
                for d in data]
        return pd.DataFrame(rows)
    return pd.DataFrame([data])


def _read_unknown(path: str) -> pd.DataFrame:
    """Last-resort reader for files with no / unrecognized extension.

    Archive and repo dumps (e.g. UCI exports) are often real CSV or JSON saved
    without an extension; sniff those before giving up so one extensionless file
    doesn't fail the whole source.
    """
    attempts = (
        lambda p: pd.read_json(p, lines=True),
        lambda p: pd.read_json(p),
        lambda p: pd.read_csv(p, low_memory=False),
        lambda p: pd.read_csv(p, sep="\t", low_memory=False),
    )
    for reader in attempts:
        try:
            df = reader(path)
            if df.shape[1] > 0 and df.shape[0] > 0:
                return df
        except Exception:
            continue
    raise ValueError(f"Unsupported file type: {path}")


def _read_textfile(path: str) -> pd.DataFrame:
    """Read a whole rule/markup file (YARA, YAML, Sigma) as ONE text record."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read().strip()
    if not content:
        return pd.DataFrame(columns=["text"])
    return pd.DataFrame([{"text": content, "_file": os.path.basename(path)}])


def read_any(path: str) -> pd.DataFrame:
    """Read csv/jsonl/json/parquet/txt/rule files into a DataFrame, robustly."""
    import pandas.errors as pd_errors
    low = path.lower()
    if low.endswith(".parquet"):
        return pd.read_parquet(path)
    if low.endswith(TEXT_FILE_EXTS):          # YARA / YAML / Sigma -> one record
        return _read_textfile(path)
    if low.endswith(".jsonl"):
        try:
            return pd.read_json(path, lines=True)
        except ValueError:
            return _read_json_repair(path)
    if low.endswith(".csv"):
        for enc in ("utf-8", "latin-1"):
            try:
                return pd.read_csv(path, low_memory=False, encoding=enc)
            except UnicodeDecodeError:
                continue
            except pd_errors.ParserError:     # inconsistent column counts
                break
        # tolerant last resort: skip malformed rows (python engine handles ragged
        # rows; it doesn't accept low_memory, so that option is omitted here)
        return pd.read_csv(path, on_bad_lines="skip", encoding="latin-1",
                           engine="python")
    if low.endswith(".json"):
        try:
            return pd.read_json(path)
        except ValueError:
            try:                                    # .json that is really JSONL
                return pd.read_json(path, lines=True)
            except ValueError:
                return _read_json_repair(path)
    if low.endswith(".xlsx"):
        return pd.read_excel(path, engine="openpyxl")
    if low.endswith(".xls"):
        return pd.read_excel(path)
    if low.endswith(".txt"):
        try:
            df = pd.read_csv(path, header=None, low_memory=False)
        except pd_errors.ParserError:         # ragged rows (e.g. MalAPI matrix)
            df = pd.read_csv(path, header=None, on_bad_lines="skip",
                             encoding="latin-1", engine="python")
        if df.shape[1] == len(NSLKDD_COLS):
            df.columns = NSLKDD_COLS
        return df
    return _read_unknown(path)


def group_key(rel_path: str) -> str:
    """Strip HF shard suffix, keep subfolder: cve_data/train-00000-of-1 -> cve_data_train."""
    no_ext = os.path.splitext(rel_path)[0]
    no_shard = re.sub(r"-\d+-of-\d+$", "", no_ext)
    parts = no_shard.replace("\\", "/").split("/")
    if len(parts) > 1 and parts[0].lower() == "data":
        parts = parts[1:]
    return "_".join(parts)


def write_jsonl(df: pd.DataFrame, path: str) -> int:
    """Write a DataFrame to JSONL; return byte size."""
    if hasattr(df, "columns"):
        df.columns = [str(c).strip() for c in df.columns]
    df.to_json(path, orient="records", lines=True, force_ascii=False)
    return os.path.getsize(path)


# CSVs above this size stream row-by-row (constant RAM) instead of via pandas.
BIG_CSV_BYTES = 200 * 1024 * 1024

# Field names tried in order when a dataset record lacks a `text` column.
_TEXT_CANDIDATES = (
    "text", "content", "body", "description", "email_text", "source_text",
    "message", "comment", "payload", "abstract",
)
# Q&A column pairs: combine question + answer into a single text field.
_QA_PAIRS = (
    ("question", "answer"),
    ("prompt", "response"),
    ("input", "output"),
    ("instruction", "response"),
)


def enrich_df(df: pd.DataFrame, source: str, url: str, lic: str) -> pd.DataFrame:
    """Add provenance (source/url/license) and normalise the text column.

    Called on every dataset DataFrame before writing to JSONL so that the
    cleaning stage can find `source`, `url`, `license`, and `text` on every
    record regardless of the original dataset schema.
    """
    df = df.copy()
    if "source" not in df.columns:
        df["source"] = source
    if "url" not in df.columns:
        df["url"] = url
    if "license" not in df.columns:
        df["license"] = lic
    if "text" not in df.columns:
        for col in _TEXT_CANDIDATES:
            if col in df.columns:
                df["text"] = df[col].astype(str)
                break
        else:
            for q_col, a_col in _QA_PAIRS:
                if q_col in df.columns and a_col in df.columns:
                    df["text"] = df[q_col].astype(str) + "\n\n" + df[a_col].astype(str)
                    break
    return df


def _stream_csv_to_jsonl(original: str, jsonl: str, cap: int,
                          extra_fields: dict | None = None) -> int:
    """Row-by-row CSV -> JSONL with orjson; constant memory, aborts past cap."""
    import csv

    import orjson
    csv.field_size_limit(1 << 30)
    size = 0
    with open(original, newline="", encoding="utf-8", errors="replace") as f, \
            open(jsonl, "wb") as out:
        reader = csv.DictReader(f, restkey="_extra", restval="")
        for row in reader:
            row.pop(None, None)
            if extra_fields:
                for k, v in extra_fields.items():
                    if k not in row:
                        row[k] = v
            line = orjson.dumps(row) + b"\n"
            size += len(line)
            if size > cap:
                out.close(); os.remove(jsonl)
                return cap + 1
            out.write(line)
    return size


def to_jsonl(original: str, jsonl: str, cap: int = CAP_BYTES,
             *, meta: dict | None = None) -> int:
    """Convert any supported file to JSONL. Big/wide CSVs stream (constant RAM).

    `meta` (source, url, license) is injected into every record so the cleaning
    stage finds the required provenance fields regardless of original schema.
    """
    if original.lower().endswith(".csv") and os.path.getsize(original) > BIG_CSV_BYTES:
        logger.debug(f"streaming big CSV {os.path.basename(original)}")
        return _stream_csv_to_jsonl(original, jsonl, cap, extra_fields=meta)
    df = read_any(original)
    if meta:
        df = enrich_df(df, source=meta.get("source", ""),
                       url=meta.get("url", ""), lic=meta.get("license", ""))
    return write_jsonl(df, jsonl)


# ----------------------------------------------------- SQLite ingest log -----
class IngestLog:
    """Provenance + final-table store: one row per produced / skipped file."""

    COLS = ("ts", "kind", "name", "category", "domain", "description",
            "source_url", "origin_format", "orig_mb", "jsonl_mb", "rows",
            "sha256", "license", "status")

    def __init__(self, db: str = DB_PATH):
        os.makedirs(os.path.dirname(db) or ".", exist_ok=True)
        self.con = sqlite3.connect(db)
        self.con.execute(
            "CREATE TABLE IF NOT EXISTS ingest "
            "(ts TEXT, kind TEXT, name TEXT, category TEXT, domain TEXT, "
            " description TEXT, source_url TEXT, origin_format TEXT, "
            " orig_mb REAL, jsonl_mb REAL, rows INTEGER, sha256 TEXT, "
            " license TEXT, status TEXT)")
        self.con.commit()

    def record(self, **kw):
        kw.setdefault("ts", time.strftime("%Y-%m-%d %H:%M:%S"))
        vals = [kw.get(c) for c in self.COLS]
        self.con.execute(
            f"INSERT INTO ingest ({','.join(self.COLS)}) "
            f"VALUES ({','.join('?' * len(self.COLS))})", vals)
        self.con.commit()

    def table(self) -> pd.DataFrame:
        return pd.read_sql_query("SELECT * FROM ingest ORDER BY domain, name", self.con)


class _Collector:
    """Drop-in for ``IngestLog`` that buffers rows in memory instead of SQLite.

    The fetch/scrape handlers only ever call ``log.record(**kw)``, so passing a
    ``_Collector`` lets a worker process run them without touching the shared
    SQLite file. The parent later replays ``rows`` into the real ``IngestLog``.
    """

    def __init__(self):
        self.rows: list[dict] = []

    def record(self, **kw):
        kw.setdefault("ts", time.strftime("%Y-%m-%d %H:%M:%S"))
        self.rows.append({c: kw.get(c) for c in IngestLog.COLS})
