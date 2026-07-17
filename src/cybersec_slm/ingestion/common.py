#!/usr/bin/env python3
"""Ingestion-stage helpers — HTTP, robust readers, and the ingest log.

Shared concerns (logger, try_import, sha256, count_lines, paths) live in
``cybersec_slm.core``; this module adds what only ingestion needs.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time

import pandas as pd

from ..core import LOGS, RAW_DATA, count_lines, logger, sha256_file, try_import  # noqa: F401
from . import urlscreen

# ---------------------------------------------------------------- config -----
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
from tenacity import (  # noqa: E402
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

_RETRY = dict(stop=stop_after_attempt(4),
              wait=wait_exponential(multiplier=1, min=2, max=30),
              retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException)),
              reraise=True)


# How many hops a fetch will follow before giving up. httpx's own default is 20;
# a corpus source that needs more than a handful is broken, not shy.
MAX_REDIRECTS = 10


def _screened_hops(url: str, timeout: int, opener):
    """Walk the redirect chain, screening every hop, and return the final response.

    ``follow_redirects=True`` is the natural way to write this and it is exactly
    what makes the screen useless: httpx would follow a 302 from a public URL to
    169.254.169.254 without the screen ever seeing the second URL. So redirects
    are followed by hand and :func:`urlscreen.check` runs on each hop.

    ``opener`` returns a response for one hop, so the streaming and non-streaming
    callers share this logic without one of them buffering the whole body.
    """
    seen: list[str] = []
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        urlscreen.check(current)
        resp = opener(current, timeout)
        location = resp.headers.get("location") if resp.headers else None
        if not (getattr(resp, "is_redirect", False) and location):
            return resp
        seen.append(current)
        # A Location may be relative; resolve against the hop it came from, or the
        # screen would run on a fragment and pass it for the wrong reason.
        current = str(httpx.URL(current).join(location))
        if hasattr(resp, "close"):
            resp.close()
    raise httpx.HTTPError(
        f"too many redirects (> {MAX_REDIRECTS}) starting at {url!r}: {seen}")


@retry(**_RETRY)
def http_get(url: str, timeout: int = 180) -> httpx.Response:
    """GET a screened URL, following (and re-screening) redirects by hand."""
    def _open(u, t):
        return httpx.get(u, headers=HEADERS, follow_redirects=False, timeout=t)

    r = _screened_hops(url, timeout, _open)
    r.raise_for_status()
    return r


@retry(**_RETRY)
def download(url: str, dest: str) -> tuple[int, str]:
    """Stream a screened URL to disk; return (bytes, sha256)."""
    import hashlib
    h = hashlib.sha256()
    size = 0
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)

    def _open(u, t):
        ctx = httpx.stream("GET", u, headers=HEADERS, follow_redirects=False,
                           timeout=t)
        return ctx.__enter__()

    r = _screened_hops(url, 180, _open)
    try:
        r.raise_for_status()
        with open(dest, "wb") as f:
            for chunk in r.iter_bytes(1 << 16):
                size += len(chunk)
                f.write(chunk); h.update(chunk)
    finally:
        if hasattr(r, "close"):
            r.close()
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
    with open(path, encoding="utf-8", errors="replace") as f:
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
    with open(path, encoding="utf-8", errors="replace") as f:
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


# Files above this size take the polars lazy fast path (or the CSV row-streamer
# fallback) instead of loading whole into pandas.
BIG_FILE_BYTES = 200 * 1024 * 1024

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


def _polars_enrich(lf, meta: dict | None):
    """Add source/url/license + a derived text column to a lazy frame.

    Mirrors ``enrich_df`` so a polars-converted file carries the same provenance
    fields the cleaning stage expects, regardless of the original schema.
    """
    import polars as pl

    cols = set(lf.collect_schema().names())
    if not meta:
        return lf
    additions = []
    for field in ("source", "url", "license"):
        if field not in cols:
            additions.append(pl.lit(meta.get(field, "")).alias(field))
    if additions:
        lf = lf.with_columns(additions)
    if "text" not in cols:
        text_col = next((c for c in _TEXT_CANDIDATES if c in cols), None)
        if text_col is not None:
            lf = lf.with_columns(pl.col(text_col).cast(pl.Utf8).alias("text"))
        else:
            for q_col, a_col in _QA_PAIRS:
                if q_col in cols and a_col in cols:
                    lf = lf.with_columns(
                        (pl.col(q_col).cast(pl.Utf8) + pl.lit("\n\n")
                         + pl.col(a_col).cast(pl.Utf8)).alias("text"))
                    break
    return lf


def _polars_to_jsonl(original: str, jsonl: str, meta: dict | None) -> int:
    """Lazy-scan a large csv/parquet/jsonl and stream it to JSONL via polars.

    Returns the output byte size. Raises for any unsupported extension or scan
    error so the caller can fall back to the pandas path.
    """
    import polars as pl

    low = original.lower()
    if low.endswith(".csv"):
        lf = pl.scan_csv(original, ignore_errors=True, infer_schema_length=1000)
    elif low.endswith(".parquet"):
        lf = pl.scan_parquet(original)
    elif low.endswith(".jsonl"):
        lf = pl.scan_ndjson(original)
    else:
        raise ValueError(f"polars fast path unsupported for {original}")
    lf = _polars_enrich(lf, meta)
    lf.sink_ndjson(jsonl)
    return os.path.getsize(jsonl)


def to_jsonl(original: str, jsonl: str, *, meta: dict | None = None) -> int:
    """Convert any supported file to JSONL.

    Large csv/parquet/jsonl take the polars lazy fast path (constant RAM, fast);
    a polars failure or an exotic format falls back to the pandas reader. `meta`
    (source, url, license) is injected into every record so the cleaning stage
    finds provenance regardless of the original schema.
    """
    low = original.lower()
    if (low.endswith((".csv", ".parquet", ".jsonl"))
            and os.path.getsize(original) > BIG_FILE_BYTES):
        try:
            return _polars_to_jsonl(original, jsonl, meta)
        except Exception as ex:
            logger.warning(f"polars fast path failed for {os.path.basename(original)}: "
                           f"{type(ex).__name__}: {ex}; falling back to pandas")
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

    def record_many(self, rows: list[dict]) -> None:
        """Insert many rows in one transaction (a single commit/fsync).

        Used by the streaming parent to replay each source's buffered ingest rows;
        far cheaper than committing per row when there are many sources/files.
        """
        if not rows:
            return
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        vals = [[(kw.get("ts") or now) if c == "ts" else kw.get(c)
                 for c in self.COLS] for kw in rows]
        self.con.executemany(
            f"INSERT INTO ingest ({','.join(self.COLS)}) "
            f"VALUES ({','.join('?' * len(self.COLS))})", vals)
        self.con.commit()

    def table(self) -> pd.DataFrame:
        return pd.read_sql_query("SELECT * FROM ingest ORDER BY domain, name", self.con)

    def export_ledger(self, path: str | None = None) -> str:
        """Write the provenance ledger (one row per produced/skipped file) to CSV.

        Version-controlled / DVC-tracked, this is the trace that lets a toxic or
        mis-licensed source be scoped and surgically removed later rather than
        forcing the whole corpus to be discarded (threat model: Licensing and
        Provenance as a Security Control).
        """
        path = path or os.path.join(LOGS, "provenance", "ledger.csv")
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.table().to_csv(path, index=False)
        logger.info(f"provenance ledger -> {path}")
        return path


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
