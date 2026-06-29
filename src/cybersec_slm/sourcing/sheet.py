#!/usr/bin/env python3
"""Google Sheet I/O for sourcing: read existing links (dedup) + append rows.

Two access paths, on purpose:

* **Dedup read** uses the *public* CSV export (no credentials), so dry runs can
  compute "what's new" without any Google auth. Requires the sheet to be shared
  as "Anyone with the link -> Viewer" (the rest of the pipeline already relies
  on this for ``extraction.sources``).
* **Append** uses the Sheets API with a service-account credential that has
  edit access to the sheet — the only operation that actually writes.

URL normalization (:func:`normalize_url`) is what makes "already exists" robust:
scheme, ``www.``, trailing slashes, query strings and fragments are stripped so
the same dataset linked two slightly different ways is still recognized as one.
"""

from __future__ import annotations

import csv
import io
import os
import re
from urllib.parse import urlparse

_ID_RE = re.compile(r"/spreadsheets/d/([A-Za-z0-9_-]+)")
_LINK_HEADERS = ("dataset link", "url", "link", "dataset_link", "source url")


def extract_spreadsheet_id(url_or_id: str) -> str:
    """Accept a full Sheets URL or a bare id and return the id."""
    m = _ID_RE.search(url_or_id or "")
    if m:
        return m.group(1)
    return (url_or_id or "").strip()


def normalize_url(url: str) -> str:
    """Canonical form used for dedup comparisons (not for storage)."""
    s = (url or "").strip().lower()
    if not s:
        return ""
    p = urlparse(s if "://" in s else "//" + s, scheme="https")
    host = p.netloc.removeprefix("www.")
    path = p.path.rstrip("/")
    return f"{host}{path}"


def _links_from_csv(text: str) -> set[str]:
    """Extract the normalized link set from an exported-sheet CSV string."""
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    if not rows:
        return set()
    header = [h.strip().lower() for h in rows[0]]
    idx = next((i for i, h in enumerate(header) if h in _LINK_HEADERS), None)
    if idx is None:
        return set()
    links: set[str] = set()
    for row in rows[1:]:
        if idx < len(row):
            norm = normalize_url(row[idx])
            if norm:
                links.add(norm)
    return links


def existing_links(spreadsheet_id: str, *, client=None) -> set[str]:
    """Normalized set of links already in the sheet (via public CSV export)."""
    export = (f"https://docs.google.com/spreadsheets/d/{spreadsheet_id}"
              "/export?format=csv")
    import httpx
    owns = client is None
    client = client or httpx.Client(timeout=30, follow_redirects=True)
    try:
        resp = client.get(export)
        resp.raise_for_status()
    finally:
        if owns:
            client.close()
    return _links_from_csv(resp.text)


def _build_service(creds_path: str):
    """Build an authenticated Sheets API client (lazy, optional deps)."""
    try:
        from google.oauth2.service_account import Credentials
        from googleapiclient.discovery import build
    except ImportError as e:                                  # pragma: no cover
        raise RuntimeError(
            "Appending to the sheet needs google-api-python-client + google-auth "
            "(base deps — run `uv sync` to install them)."
        ) from e
    scopes = ["https://www.googleapis.com/auth/spreadsheets"]
    creds = Credentials.from_service_account_file(creds_path, scopes=scopes)
    return build("sheets", "v4", credentials=creds, cache_discovery=False)


def append_rows(spreadsheet_id: str, rows: list[list[str]], *,
                creds_path: str, sheet_name: str | None = None) -> int:
    """Append ``rows`` (lists of cell values) to the sheet; return count.

    Uses ``values.append`` with ``INSERT_ROWS`` so existing data is never
    overwritten — new rows land after the current content.
    """
    if not rows:
        return 0
    if not creds_path or not os.path.exists(creds_path):
        raise RuntimeError(
            f"service-account credentials not found at {creds_path!r}; set "
            "GOOGLE_SHEETS_CREDENTIALS to the JSON key path (or use --dry-run).")
    service = _build_service(creds_path)
    rng = f"{sheet_name}!A1" if sheet_name else "A1"
    service.spreadsheets().values().append(
        spreadsheetId=spreadsheet_id,
        range=rng,
        valueInputOption="USER_ENTERED",
        insertDataOption="INSERT_ROWS",
        body={"values": rows},
    ).execute()
    return len(rows)
