#!/usr/bin/env python3
"""Source mappers + registry dispatch (flowchart: Source Mapper, Registry Dispatch).

A *mapper* turns one cleaned record (whatever its original schema) into the
canonical field dict that :class:`~cybersec_slm.normalize.schema.CanonicalRecord`
expects. ``BaseMapper`` (an ``abc.ABC``) enforces ``.map()`` on every subclass;
two concrete strategies cover the two record shapes the corpus actually contains:

  * ``ProseMapper``     — records whose payload is natural-language ``text``.
  * ``StructuredMapper``— feature/table rows: serialize the salient columns into
                          a readable "key: value" sentence so they still carry text.

Mappers register themselves in ``MAPPER_REGISTRY`` via ``@register_mapper(name)``.
``get_mapper`` dispatches per source; the first time an unknown source appears it
is counted (``collections.Counter``) and a loguru first-sight alert fires, then it
falls back to a sensible default rather than dropping the record.
"""

from __future__ import annotations

import abc
import re
from collections import Counter

from ..core import logger

# ------------------------------------------------------------------ re cleaning
_WS = re.compile(r"[ \t ]+")
_NL = re.compile(r"\n{3,}")
# Common scraped/boilerplate lines to strip before a record becomes corpus text.
_BOILERPLATE = re.compile(
    r"(?im)^\s*(cookie policy|all rights reserved|terms of service|"
    r"privacy policy|subscribe to our newsletter|share this article|"
    r"click here to|read more\b.*|copyright\s*©?.*)\s*$")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def clean_text(text: str) -> str:
    """Normalize whitespace and strip boilerplate lines (the ``re`` node)."""
    if not text:
        return ""
    text = _CTRL.sub("", text)
    text = _BOILERPLATE.sub("", text)
    text = _WS.sub(" ", text)
    text = _NL.sub("\n\n", text)
    return text.strip()


# Fields that are pipeline bookkeeping, never corpus content.
_RESERVED = {"source", "url", "license", "text", "_text_field"}
# Annotation/provenance keys added by the cleaning stage (leading underscore).
_INTERNAL_PREFIX = "_"

# Original file extension -> origin_format (best-effort; cleaned records are jsonl
# by the time normalize runs, so default to that when no hint survives).
_FMT_BY_EXT = {
    ".parquet": "parquet", ".csv": "csv", ".json": "json", ".jsonl": "jsonl",
    ".xlsx": "xlsx", ".xls": "xls", ".txt": "txt", ".pdf": "pdf", ".xml": "xml",
    ".yar": "yara", ".yara": "yara", ".yml": "yaml", ".yaml": "yaml", ".md": "markdown",
}


def _infer_origin_format(rec: dict) -> str:
    hint = rec.get("_file") or rec.get("_source_file") or ""
    if isinstance(hint, str) and "." in hint:
        ext = "." + hint.rsplit(".", 1)[-1].lower()
        if ext in _FMT_BY_EXT:
            return _FMT_BY_EXT[ext]
    return "jsonl"


# --------------------------------------------------------------- mapper registry
MAPPER_REGISTRY: dict[str, BaseMapper] = {}
_UNMAPPED: Counter[str] = Counter()        # sources with no dedicated mapper


def register_mapper(name: str):
    """Class decorator: instantiate and register a mapper under ``name``."""
    def _wrap(cls):
        MAPPER_REGISTRY[name] = cls()
        return cls
    return _wrap


class BaseMapper(abc.ABC):
    """Abstract base — every subclass must implement :meth:`map`."""

    @abc.abstractmethod
    def map(self, rec: dict, *, domain: str, source: str) -> dict | None:
        """Return the intermediate text+provenance dict, or ``None`` to drop.

        Output keys: ``text, source, source_url, license, origin_format,
        source_file, raw_domain``. :func:`cybersec_slm.normalize.enrich.build_record`
        turns that into the full canonical record (id, hashes, labels, ...).
        """
        raise NotImplementedError

    # -- shared helpers ------------------------------------------------------
    @staticmethod
    def _str_or(value, fallback=None):
        """Non-empty string, else the fallback (record fields are often NaN/None)."""
        return value.strip() if isinstance(value, str) and value.strip() else fallback

    def _base(self, rec: dict, text: str, domain: str, source: str) -> dict:
        # ``source`` is provenance: which source folder this record came from. Only
        # the pipeline knows that, so it is never read off the record. Whatever a
        # record calls "source" is the dataset author's own notion (a citation, a
        # URL, a sentence of prose), and trusting it let ingestion's bug (it wrote
        # the description into every record's source, see fetch._convert_and_log)
        # reach the manifest: 61% of the live corpus was filed under 188 prose
        # "sources", which made the funnel's Final row claim more sources than
        # data/clean has folders. Reading provenance from the pipeline keeps this
        # true whatever the records happen to carry.
        return {
            "text": text,
            "source": source,
            "source_url": self._str_or(rec.get("url")),
            "license": self._str_or(rec.get("license")) or "",
            "origin_format": _infer_origin_format(rec),
            "source_file": source,
            "raw_domain": domain,
        }


@register_mapper("prose")
class ProseMapper(BaseMapper):
    """Default mapper: the cleaned ``text`` field is already prose."""

    def map(self, rec: dict, *, domain: str, source: str) -> dict | None:
        text = clean_text(rec.get("text") or "")
        if not text:
            return None
        return self._base(rec, text, domain, source)


@register_mapper("structured")
class StructuredMapper(BaseMapper):
    """Feature/table rows: render salient columns into a readable sentence so the
    row still contributes text instead of being dropped as no-prose."""

    _SKIP = _RESERVED | {"id", "index", "unnamed: 0"}
    _MAX_FIELDS = 40

    def map(self, rec: dict, *, domain: str, source: str) -> dict | None:
        # If the cleaning stage already produced prose text, prefer it.
        existing = clean_text(rec.get("text") or "")
        if existing:
            return self._base(rec, existing, domain, source)
        parts: list[str] = []
        for k, v in rec.items():
            if k.lower() in self._SKIP or k.startswith(_INTERNAL_PREFIX):
                continue
            if v is None or v == "":
                continue
            parts.append(f"{k}: {v}")
            if len(parts) >= self._MAX_FIELDS:
                break
        if not parts:
            return None
        text = clean_text("; ".join(parts))
        return self._base(rec, text, domain, source)


# ----------------------------------------------------------------- dispatch ----
def get_mapper(source: str, rec: dict) -> BaseMapper:
    """Pick a mapper for ``source``.

    Explicitly-registered source names win. Otherwise choose by record shape:
    a usable ``text`` field -> prose, else structured. First sighting of an
    unregistered source raises a loguru alert and is counted as unmapped.
    """
    if source in MAPPER_REGISTRY:
        return MAPPER_REGISTRY[source]

    if _UNMAPPED[source] == 0:
        logger.warning(f"normalize: no dedicated mapper for source '{source}' "
                       f"— dispatching by record shape")
    _UNMAPPED[source] += 1

    text = rec.get("text")
    if isinstance(text, str) and text.strip():
        return MAPPER_REGISTRY["prose"]
    return MAPPER_REGISTRY["structured"]


def unmapped_sources() -> dict[str, int]:
    """Sources that fell back to shape dispatch, with hit counts (for the report)."""
    return dict(_UNMAPPED)
