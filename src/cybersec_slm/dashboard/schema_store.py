#!/usr/bin/env python3
"""Editable field catalog for the canonical record schema.

The 22-field contract lives in :mod:`cybersec_slm.normalize.schema` as the
``CanonicalRecord`` Pydantic model. This module exposes those fields as a plain
list of dicts the dashboard can render and edit, and persists *annotations* (a
human description and a documented default) to a JSON sidecar at the data root.

Overrides are documentation only: they never touch validation, so a mistaken
edit can't break the pipeline. Only the diff against the model baseline is
saved, so genuine schema changes still flow through untouched fields.
"""

from __future__ import annotations

import json
import os
import typing

from .. import core
from ..normalize.schema import CanonicalRecord

FILE_NAME = "schema_fields.json"

# Columns the user may edit; the rest are derived from the model and read-only.
EDITABLE = ("default", "description")


def overrides_path(path: str | None = None) -> str:
    return path or os.path.join(core.data_root(), FILE_NAME)


def _type_name(annotation) -> str:
    """A short, readable label for a field annotation (``str | None`` etc.)."""
    args = typing.get_args(annotation)
    if args:
        parts = [getattr(a, "__name__", str(a)) for a in args if a is not type(None)]
        label = " | ".join(parts)
        return f"{label} | None" if type(None) in args else label
    return getattr(annotation, "__name__", str(annotation))


def _model_baseline() -> dict[str, dict[str, str]]:
    """Model-derived ``{field: {default, description}}`` strings to diff against."""
    base: dict[str, dict[str, str]] = {}
    for name, field in CanonicalRecord.model_fields.items():
        default = "" if field.is_required() or field.default is None else str(field.default)
        base[name] = {"default": default, "description": field.description or ""}
    return base


def _load(path: str | None = None) -> dict:
    try:
        with open(overrides_path(path), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def field_catalog(path: str | None = None) -> list[dict]:
    """The full field list: model facts merged with any saved annotations."""
    saved = _load(path)
    base = _model_baseline()
    rows = []
    for name, field in CanonicalRecord.model_fields.items():
        ov = saved.get(name) if isinstance(saved.get(name), dict) else {}
        rows.append({
            "field": name,
            "type": _type_name(field.annotation),
            "required": field.is_required(),
            "default": ov.get("default", base[name]["default"]),
            "description": ov.get("description", base[name]["description"]),
        })
    return rows


def save_overrides(rows, path: str | None = None) -> str:
    """Persist edited ``default`` / ``description`` values (diff vs. the model)."""
    p = overrides_path(path)
    base = _model_baseline()
    out: dict[str, dict[str, str]] = {}
    for r in rows:
        name = r.get("field")
        if name not in CanonicalRecord.model_fields:
            continue
        entry = {k: str(r.get(k, "") or "") for k in EDITABLE
                 if str(r.get(k, "") or "") != base[name][k]}
        if entry:
            out[name] = entry
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    tmp = f"{p}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    os.replace(tmp, p)
    return p
