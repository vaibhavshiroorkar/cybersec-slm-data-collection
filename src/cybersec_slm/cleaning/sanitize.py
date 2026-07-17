#!/usr/bin/env python3
"""Structural Sanitization — the first stage.

Fixes encoding (ftfy when available, else a mojibake heuristic), normalizes
unicode to NFC, strips control characters and collapses whitespace, normalizes
existing required fields (without fabricating missing ones — the normalize stage
supplies provenance defaults), and normalizes date-ish fields to ISO-8601.

Public API:
    sanitize_text(s) -> str
    sanitize_record(rec) -> (rec, changed: bool)
"""

from __future__ import annotations

import re
import unicodedata

from .common import DATE_FIELDS, logger, try_import

REQUIRED_FIELDS = ("source", "url", "license", "text")

_ftfy = try_import("ftfy")
_dateutil = try_import("dateutil.parser")

# ftfy normalizes to NFC itself, which `sanitize_text` then immediately redoes on
# the next line — so turn ftfy's copy off and pay for it once. Measured 1.12 ->
# 0.90 ms/record with byte-identical output.
#
# Note this config only drops the *duplicate* pass; every repair stays on. Do not
# be tempted to skip ftfy entirely on records with no mojibake marker: on this
# corpus fix_text changes 36/500 records and NONE of them carry one (they are
# uncurl_quotes, not encoding damage), and ftfy.badness.is_bad flags 0/500 of
# them — so both "cheap guards" silently alter 7% of the corpus.
_FTFY_CFG = _ftfy.TextFixerConfig(normalization=None) if _ftfy is not None else None
if _ftfy is None:
    logger.debug("sanitize: ftfy not found -> heuristic encoding fix")
if _dateutil is None:
    logger.debug("sanitize: dateutil not found -> dates left as-is unless ISO-parseable")

# Control chars to drop (keep \t \n \r). C0 minus tab/newline/CR, plus DEL & C1.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_WS_RUN_RE = re.compile(r"[ \t\f\v]+")          # runs of inline whitespace
_BLANKLINES_RE = re.compile(r"\n{3,}")           # 3+ newlines -> 2


def fix_encoding(s: str) -> str:
    """Repair mojibake. ftfy if present, else a common latin1<->utf8 heuristic."""
    if _ftfy is not None:
        return _ftfy.fix_text(s, config=_FTFY_CFG)
    # Heuristic: text that was utf-8 decoded as latin-1 shows chars like Ã©, â€™.
    if any(m in s for m in ("Ã", "Â", "â€")):
        try:
            return s.encode("latin-1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
    return s


def sanitize_text(s: str) -> str:
    """Encoding fix -> NFC -> drop control chars -> collapse whitespace."""
    if not isinstance(s, str):
        s = "" if s is None else str(s)
    s = fix_encoding(s)
    s = unicodedata.normalize("NFC", s)
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = _CONTROL_RE.sub("", s)
    s = _WS_RUN_RE.sub(" ", s)
    s = _BLANKLINES_RE.sub("\n\n", s)
    # trim trailing spaces on each line, then overall
    s = "\n".join(line.rstrip() for line in s.split("\n"))
    return s.strip()


def _to_iso(value):
    """Return an ISO-8601 string for a date-ish value, or the original."""
    if not isinstance(value, str) or not value.strip():
        return value
    if _dateutil is not None:
        try:
            return _dateutil.parse(value).date().isoformat()
        except (ValueError, OverflowError):
            return value
    # stdlib best-effort: accept a few unambiguous formats.
    from datetime import datetime
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%Y/%m/%d", "%d-%m-%Y",
                "%B %d, %Y", "%d %B %Y"):
        try:
            return datetime.strptime(value.strip(), fmt).date().isoformat()
        except ValueError:
            continue
    return value


def sanitize_record(rec: dict) -> tuple[dict, bool]:
    """Return (sanitized_record, changed). Normalizes existing required fields
    (None -> ""), cleans text, and normalizes any date-ish fields to ISO. Missing
    provenance fields are *not* fabricated here — the normalize mappers default
    them (see normalize/mappers.py::BaseMapper._base)."""
    out = dict(rec)
    changed = False

    for field in REQUIRED_FIELDS:               # normalize existing fields only
        if field in out and out[field] is None:
            out[field] = ""
            changed = True

    if "text" in out and isinstance(out.get("text"), str):
        raw_text = out["text"]
        clean = sanitize_text(raw_text)
        if clean != raw_text:
            changed = True
        out["text"] = clean

    # also tidy short metadata strings
    for field in ("source", "license"):
        if isinstance(out.get(field), str):
            tidy = sanitize_text(out[field])
            if tidy != out[field]:
                out[field] = tidy
                changed = True

    for field in DATE_FIELDS:                    # normalize dates if present
        if field in out:
            iso = _to_iso(out[field])
            if iso != out[field]:
                out[field] = iso
                changed = True

    return out, changed
