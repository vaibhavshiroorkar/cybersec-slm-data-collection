#!/usr/bin/env python3
"""Version-controlled source allowlist (the highest-leverage anti-poisoning control).

Only sources explicitly marked ``approved`` in ``sources/allowlist.yaml`` are
fetched. Everything else (``pending`` / ``rejected`` / unknown) is skipped and
logged, so a compromised or substituted upstream cannot quietly enter the corpus
under a name we expect (threat model Stage 1: "Source Compromise / Substitution",
gap: "Implicit Trust").

Enforcement is on by default *when the allowlist file exists*. If it is absent the
gate fails open (allow-all) with a warning, so a fresh checkout still runs; set
``CYBERSEC_SLM_ENFORCE_ALLOWLIST=1`` to require the file, or ``=0`` to disable the
gate entirely.

Public API:
    descriptor_key(descriptor) -> str          # stable identity for a source
    is_allowed(descriptor)     -> (bool, str)  # (allowed?, reason)
    load_allowlist(path=None)  -> dict
    dump_allowlist_yaml(descriptors, status="approved") -> str
"""

from __future__ import annotations

import os
from functools import lru_cache

import yaml

from ..core import logger

# sources/allowlist.yaml lives next to the code repo, not the (relocatable) data
# root — it is curated and version-controlled. Resolve relative to this file's
# package, walking up to the project root.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
DEFAULT_ALLOWLIST = os.path.join(_PKG_ROOT, "sources", "allowlist.yaml")

APPROVED = "approved"
_VALID_STATUS = {"approved", "pending", "rejected"}


def descriptor_key(d: dict) -> str:
    """Stable identity string for a source descriptor (matches the yaml ``id``)."""
    kind = d.get("kind")
    if kind in ("hf", "kaggle"):
        return f"{kind}:{d.get('ref')}"
    url = d.get("url") or d.get("start_url")
    if url:
        return str(url).strip()
    return f"{kind}:{d.get('ref') or d.get('slug')}"


def _enforce_flag(file_exists: bool) -> bool:
    """Whether to enforce: env override wins, else enforce iff the file exists."""
    env = os.environ.get("CYBERSEC_SLM_ENFORCE_ALLOWLIST")
    if env is not None:
        return env.strip().lower() in ("1", "true", "yes", "on")
    return file_exists


@lru_cache(maxsize=4)
def load_allowlist(path: str | None = None) -> tuple:
    """Load the allowlist into a hashable ``(enforce, frozenset(approved_keys))``.

    Cached so the per-source gate does not re-read the file for every descriptor.
    Returns approved keys indexed by both ``id`` and ``url`` for tolerant matching.
    """
    path = path or DEFAULT_ALLOWLIST
    if not os.path.exists(path):
        return (_enforce_flag(False), frozenset())
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    enforce = bool(doc.get("enforce", True))
    enforce = _enforce_flag(True) if os.environ.get(
        "CYBERSEC_SLM_ENFORCE_ALLOWLIST") is not None else enforce
    keys: set[str] = set()
    for entry in doc.get("sources", []):
        status = str(entry.get("status", "pending")).strip().lower()
        if status not in _VALID_STATUS:
            logger.warning(f"allowlist: unknown status {status!r} for "
                           f"{entry.get('id')!r} — treating as pending")
        if status == APPROVED:
            for k in (entry.get("id"), entry.get("url")):
                if k:
                    keys.add(str(k).strip())
    return (enforce, frozenset(keys))


def is_allowed(descriptor: dict, path: str | None = None) -> tuple[bool, str]:
    """Return ``(allowed, reason)`` for a source descriptor.

    Fails open (allow-all) when no allowlist file is present unless enforcement is
    forced via ``CYBERSEC_SLM_ENFORCE_ALLOWLIST=1``.
    """
    enforce, approved = load_allowlist(path)
    if not enforce:
        return True, "allowlist-disabled"
    key = descriptor_key(descriptor)
    url = (descriptor.get("url") or descriptor.get("start_url") or "").strip()
    if key in approved or (url and url in approved):
        return True, "approved"
    return False, "not-approved"


# --------------------------------------------------------------- generation ----
def dump_allowlist_yaml(descriptors: list[dict], status: str = APPROVED) -> str:
    """Render a starter allowlist.yaml for the given descriptors (curated catalog).

    Manifest sources are already vetted, so they default to ``approved``;
    spreadsheet-discovered sources should be seeded ``pending`` instead.
    """
    rows = []
    for d in descriptors:
        rows.append({
            "id": descriptor_key(d),
            "kind": d.get("kind"),
            "domain": d.get("domain"),
            "license": d.get("license"),
            "url": d.get("url") or d.get("start_url"),
            "status": status,
        })
    rows.sort(key=lambda r: (r["domain"] or "", r["id"]))
    header = ("# Version-controlled source allowlist. Only `status: approved` sources\n"
              "# are fetched (extraction/allowlist.py). Edit deliberately; changes here\n"
              "# should go through peer review (threat model: Access Control).\n")
    body = yaml.safe_dump({"version": 1, "enforce": True, "sources": rows},
                          sort_keys=False, allow_unicode=True, width=100)
    return header + body
