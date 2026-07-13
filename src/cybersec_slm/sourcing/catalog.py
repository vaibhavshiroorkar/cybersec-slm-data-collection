#!/usr/bin/env python3
"""Editable, persistent keyword catalog for the sourcing stage.

The sub-domains and their per-mode search keywords live in an editable YAML file
(``sources/keywords.yaml`` under the data root) so the dashboard and the CLI share
one source of truth and edits survive restarts. When the file is absent, the
built-in defaults in :mod:`cybersec_slm.sourcing.keywords` are used, so nothing
breaks on a fresh checkout.

A catalog is a plain dict::

    {"<Sub-Domain>": {"datasets": [kw, ...], "text": [kw, ...]}, ...}

This module is Streamlit-free and side-effect-light (it only touches the YAML
file), so it is unit-testable directly.
"""

from __future__ import annotations

import os

from .. import core
from . import keywords as kw

CATALOG_NAME = "keywords.yaml"
MODES: tuple[str, ...] = kw.MODES               # ("datasets", "text", "both")


def catalog_path(path: str | None = None) -> str:
    """Resolve the catalog file path (arg > ``sources/keywords.yaml``)."""
    return path or os.path.join(core.data_root(), "sources", CATALOG_NAME)


def _defaults() -> dict:
    """Build the catalog from the built-in keyword lists (the code fallback)."""
    out: dict[str, dict[str, list[str]]] = {}
    for name in kw.DOMAIN_KEYWORDS:
        out[name] = {"datasets": list(kw.DOMAIN_KEYWORDS.get(name, [])),
                     "text": list(kw.DOMAIN_TEXT_KEYWORDS.get(name, []))}
    return out


def _normalize(subs: dict) -> dict:
    out: dict[str, dict[str, list[str]]] = {}
    for name, spec in (subs or {}).items():
        spec = spec or {}
        out[str(name)] = {
            "datasets": [str(k).strip() for k in (spec.get("datasets") or []) if str(k).strip()],
            "text": [str(k).strip() for k in (spec.get("text") or []) if str(k).strip()],
        }
    return out


def load(path: str | None = None) -> dict:
    """Load the catalog from YAML, falling back to the built-in defaults."""
    p = catalog_path(path)
    if not os.path.exists(p):
        return _defaults()
    import yaml
    with open(p, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    cat = _normalize(data.get("subdomains") or {})
    return cat or _defaults()


def save(cat: dict, path: str | None = None) -> str:
    """Write the catalog to YAML (creating the parent dir); return the path."""
    p = catalog_path(path)
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    import yaml
    with open(p, "w", encoding="utf-8") as f:
        yaml.safe_dump({"subdomains": _normalize(cat)}, f, sort_keys=True,
                       allow_unicode=True, default_flow_style=False)
    return p


def subdomains(cat: dict | None = None) -> list[str]:
    """Sorted list of sub-domain names in the catalog."""
    return sorted((cat if cat is not None else load()).keys())


def keywords_for(name: str, mode: str = "datasets", cat: dict | None = None) -> list[str]:
    """Keywords for one sub-domain in ``mode`` (``datasets``/``text``/``both``)."""
    cat = cat if cat is not None else load()
    spec = cat.get(name, {})
    if mode == "both":
        return list(spec.get("datasets", [])) + list(spec.get("text", []))
    return list(spec.get(mode, []))


def keyword_sets(mode: str = "datasets",
                 cat: dict | None = None) -> list[tuple[dict[str, list[str]], str]]:
    """Return ``[(keyword_dict, qualifier), ...]`` for ``mode`` from the catalog.

    Mirrors :func:`cybersec_slm.sourcing.keywords.keyword_sets` but reads the live
    (persisted) catalog and pairs each mode with its query qualifier.
    """
    cat = cat if cat is not None else load()
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode!r}; valid: {MODES}")
    modes = ["datasets", "text"] if mode == "both" else [mode]
    qualifiers = {"datasets": kw.QUERY_QUALIFIER, "text": kw.TEXT_QUERY_QUALIFIER}
    out: list[tuple[dict[str, list[str]], str]] = []
    for m in modes:
        kwdict = {name: list(spec.get(m, [])) for name, spec in cat.items()}
        out.append((kwdict, qualifiers[m]))
    return out


def add_subdomain(name: str, *, datasets: list[str] | None = None,
                  text: list[str] | None = None, path: str | None = None) -> dict:
    """Add (or replace) a sub-domain and persist; return the updated catalog."""
    name = (name or "").strip()
    if not name:
        raise ValueError("sub-domain name is required")
    cat = load(path)
    cat[name] = {"datasets": list(datasets or []), "text": list(text or [])}
    save(cat, path)
    return cat


def remove_subdomain(name: str, path: str | None = None) -> dict:
    """Remove a sub-domain and persist; return the updated catalog."""
    cat = load(path)
    cat.pop(name, None)
    save(cat, path)
    return cat
