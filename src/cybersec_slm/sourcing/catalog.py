#!/usr/bin/env python3
"""Editable, persistent keyword catalog for the sourcing stage.

The sub-domains and their per-mode search keywords live in an editable YAML file
(``sources/profiles/<profile>/keywords.yaml`` under the data root) so the
dashboard and the CLI share one source of truth and edits survive restarts. When
the file is absent, the active profile's built-in defaults (see
:mod:`cybersec_slm.sourcing.taxonomies`) are used, so nothing breaks on a fresh
checkout.

Which file that is depends on the **active profile** — the pipeline can build
several corpora (cybersecurity, banking compliance, ...) and each keeps its own
taxonomy and catalog. See :mod:`cybersec_slm.sourcing.profiles`. Passing an
explicit ``path`` bypasses profile resolution entirely, which is what the tests
(and any caller working on a specific file) do.

A catalog is a plain dict::

    {"<Sub-Domain>": {"datasets": [kw, ...], "text": [kw, ...],
                      "code": "ENUM_CODE", "vocab": [term, ...]}, ...}

``code`` is the schema's ``subdomain_name`` enum value for this sub-domain (blank
until a code is derived or explicitly set — see :func:`code_for`); ``vocab`` is an
optional list of short, distinctive terms used only to break domain-classification
ties during discovery (falls back to the ``datasets``+``text`` keywords when
absent). The catalog also carries one top-level ``domain_name`` label (the
schema's top-level ``domain_name`` field, e.g. ``CYBERSEC``) alongside
``subdomains`` — see :func:`domain_name`/:func:`set_domain_name`. This one file is
also the taxonomy the schema/normalize stage validates records against (see
:mod:`cybersec_slm.normalize.schema`), so editing it here reshapes both stages.

This module is Streamlit-free and side-effect-light (it only touches the YAML
file), so it is unit-testable directly.
"""

from __future__ import annotations

import os
import re

from . import keywords as kw

CATALOG_NAME = "keywords.yaml"
MODES: tuple[str, ...] = kw.MODES               # ("datasets", "text", "both")

# A Sub-Domain name is used verbatim as a directory component — ingestion writes
# to ``data/raw/<Sub-Domain>/<source>/`` (see ingestion.worker) and cleaning walks
# that tree back, reading the first level as the domain and the second as the
# source. A name containing a path separator would therefore split into two levels
# and be silently mis-parsed on the way back ("AML/KYC" -> domain "AML", source
# "KYC"). Reject those at the point of entry instead.
_UNSAFE_NAME = re.compile(r"[/\\]|^\.\.?$|^\s|\s$")


def validate_subdomain_name(name: str) -> str:
    """Return ``name`` if it is safe to use as a directory component, else raise.

    Raises ``ValueError`` for a name containing ``/`` or ``\\``, for the path
    specials ``.``/``..``, or for one with leading/trailing whitespace.
    """
    name = str(name or "")
    if not name.strip():
        raise ValueError("sub-domain name must not be blank")
    if _UNSAFE_NAME.search(name):
        raise ValueError(
            f"unsafe sub-domain name {name!r}: it is used as a directory name, so "
            "it cannot contain '/' or '\\\\', be '.'/'..', or have surrounding "
            "whitespace. Use e.g. 'AML-KYC' rather than 'AML/KYC'.")
    return name


def catalog_path(path: str | None = None) -> str:
    """Resolve the taxonomy file path (arg > the active profile's keywords.yaml)."""
    if path:
        return path
    from . import profiles
    return profiles.keywords_path()


def _taxonomy(profile: str | None = None):
    """The built-in taxonomy supplying fallbacks (named profile, else active)."""
    from . import profiles
    return profiles.taxonomy(profile)


def _defaults(profile: str | None = None) -> dict:
    """Build the catalog from a profile's built-in lists (the code fallback)."""
    t = _taxonomy(profile)
    return {name: {"datasets": list(t.datasets.get(name, [])),
                   "text": list(t.text.get(name, [])),
                   "links": [],
                   "code": t.codes.get(name, ""),
                   "vocab": sorted(t.vocab.get(name, set()))}
            for name in t.subdomains}


def _normalize(subs: dict, profile: str | None = None) -> dict:
    """Normalize a raw ``subdomains`` mapping to the full 4-key shape.

    A blank/missing ``code`` or ``vocab`` for a name that matches one of the
    profile's built-in sub-domains falls back to that sub-domain's built-in value
    (from :mod:`cybersec_slm.sourcing.taxonomies`), so a ``keywords.yaml`` written
    before these fields existed (only ``datasets``/``text``) keeps producing the
    exact same schema enum codes it always has, rather than a freshly-derived slug.
    An explicit non-blank value in the file always wins over this fallback.

    ``profile`` picks *whose* built-ins those fallbacks come from. It matters when
    reading a profile other than the active one (e.g. ``profile list``): defaulting
    to the active profile there would fill cybersec's sub-domains from ubi's
    taxonomy, silently deriving the wrong schema enum codes.
    """
    t = _taxonomy(profile)
    default_codes, default_vocab = t.codes, t.vocab
    out: dict[str, dict[str, list[str]]] = {}
    for name, spec in (subs or {}).items():
        spec = spec or {}
        name = str(name)
        code = str(spec.get("code") or "").strip() or default_codes.get(name, "")
        vocab = [str(k).strip() for k in (spec.get("vocab") or []) if str(k).strip()]
        if not vocab and name in default_vocab:
            vocab = sorted(default_vocab[name])
        out[name] = {
            "datasets": [str(k).strip() for k in (spec.get("datasets") or []) if str(k).strip()],
            "text": [str(k).strip() for k in (spec.get("text") or []) if str(k).strip()],
            "links": [str(k).strip() for k in (spec.get("links") or []) if str(k).strip()],
            "code": code,
            "vocab": vocab,
        }
    return out


def load(path: str | None = None, *, profile: str | None = None) -> dict:
    """Load the catalog from YAML, falling back to a profile's built-in defaults.

    ``profile`` names whose built-ins fill in anything the file omits; it defaults
    to the active profile. Pass it explicitly when reading a *different* profile's
    file, so its sub-domains do not inherit the active profile's enum codes.
    """
    p = catalog_path(path)
    if not os.path.exists(p):
        return _defaults(profile)
    import yaml
    with open(p, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    cat = _normalize(data.get("subdomains") or {}, profile)
    return cat or _defaults(profile)


def _read_domain_name(path: str | None, profile: str | None = None) -> str:
    """The file's ``domain_name``, else the profile's built-in label."""
    fallback = _taxonomy(profile).domain_name
    p = catalog_path(path)
    if not os.path.exists(p):
        return fallback
    import yaml
    with open(p, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    label = str(data.get("domain_name") or "").strip()
    return label or fallback


def save(cat: dict, path: str | None = None, *, domain_name: str | None = None,
         profile: str | None = None) -> str:
    """Write the catalog to YAML (creating the parent dir); return the path.

    ``domain_name`` persists the top-level schema label; when omitted, whatever is
    already on disk is preserved (or the profile's default, on a first write), so a
    call that only touches ``subdomains`` (e.g. :func:`add_subdomain`) never resets
    it. ``profile`` names whose built-ins fill any gaps — see :func:`load`.
    """
    p = catalog_path(path)
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    label = (domain_name if domain_name is not None
             else _read_domain_name(path, profile))
    import yaml
    with open(p, "w", encoding="utf-8") as f:
        yaml.safe_dump({"domain_name": label,
                        "subdomains": _normalize(cat, profile)}, f,
                       sort_keys=True, allow_unicode=True, default_flow_style=False)
    return p


def domain_name(path: str | None = None, *, profile: str | None = None) -> str:
    """The top-level schema ``domain_name`` label.

    Falls back to ``profile``'s built-in label (active profile's, when unnamed)
    for a file that does not carry one.
    """
    return _read_domain_name(path, profile)


def set_domain_name(name: str, path: str | None = None) -> str:
    """Persist the top-level ``domain_name`` label; return the catalog file path."""
    name = (name or "").strip() or kw.DEFAULT_DOMAIN_NAME
    return save(load(path), path, domain_name=name)


def _derive_code(name: str, taken: set[str]) -> str:
    """Upper-snake slug of ``name``, disambiguated against ``taken`` if needed."""
    base = re.sub(r"[^A-Za-z0-9]+", "_", name.upper()).strip("_") or "DOMAIN"
    code = base
    i = 2
    while code in taken:
        code = f"{base}_{i}"
        i += 1
    return code


def code_for(name: str, cat: dict | None = None) -> str:
    """The sub-domain's enum code: its stored ``code``, else a derived slug.

    Does not persist the derived code by itself; callers that want it saved
    (e.g. :func:`add_subdomain`) do so explicitly.
    """
    cat = cat if cat is not None else load()
    spec = cat.get(name) or {}
    stored = str(spec.get("code") or "").strip()
    if stored:
        return stored
    taken = {str(s.get("code") or "").strip() for s in cat.values()} - {""}
    return _derive_code(name, taken)


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
                  text: list[str] | None = None, links: list[str] | None = None, code: str | None = None,
                  vocab: list[str] | None = None,
                  path: str | None = None) -> dict:
    """Add (or replace) a sub-domain and persist; return the updated catalog.

    ``code`` is the schema enum code for this sub-domain; when omitted, one is
    derived from ``name`` (see :func:`_derive_code`) and persisted so it stays
    stable across future loads.
    """
    name = validate_subdomain_name((name or "").strip())
    cat = load(path)
    taken = {str(s.get("code") or "").strip() for s in cat.values()} - {""}
    cat[name] = {"datasets": list(datasets or []), "text": list(text or []), "links": list(links or []),
                "code": (code or "").strip() or _derive_code(name, taken),
                "vocab": list(vocab or [])}
    save(cat, path)
    return cat


def update_subdomain(old_name: str, *, name: str | None = None,
                     datasets: list[str] | None = None,
                     text: list[str] | None = None, links: list[str] | None = None, code: str | None = None,
                     vocab: list[str] | None = None,
                     path: str | None = None) -> dict:
    """Edit an existing sub-domain in place (optionally renaming it); persist.

    Every field is optional and ``None`` means "leave as it is", so a caller can
    rename without restating the keywords (or rewrite the keywords without
    touching the name). ``name`` renames the sub-domain, keeping its existing
    ``code`` so the schema enum value a rename produces does not silently change
    under already-normalized records — pass ``code`` explicitly to change it too.

    Raises ``KeyError`` when ``old_name`` is not in the catalog and ``ValueError``
    when a rename would collide with another existing sub-domain (which would
    otherwise silently overwrite it).

    Note this only renames the *taxonomy* entry; catalog rows in ``Sources.csv``
    still carry the old Sub-Domain label. See
    :func:`cybersec_slm.sourcing.sheet.rename_subdomain` for relabelling those.
    """
    cat = load(path)
    if old_name not in cat:
        raise KeyError(f"unknown sub-domain: {old_name!r}")
    spec = dict(cat[old_name])
    new_name = validate_subdomain_name((name or "").strip() or old_name)
    if new_name != old_name and new_name in cat:
        raise ValueError(f"sub-domain {new_name!r} already exists")

    if datasets is not None:
        spec["datasets"] = list(datasets)
    if text is not None:
        spec["text"] = list(text)
    if links is not None:
        spec["links"] = list(links)
    if vocab is not None:
        spec["vocab"] = list(vocab)
    if code is not None:
        # An explicitly blank code re-derives one from the (possibly new) name.
        taken = ({str(s.get("code") or "").strip() for n, s in cat.items()
                  if n != old_name} - {""})
        spec["code"] = code.strip() or _derive_code(new_name, taken)

    # Rebuild preserving insertion order, so a rename keeps the entry in place
    # rather than moving it to the end of the file's subdomains block.
    cat = {(new_name if n == old_name else n): (spec if n == old_name else s)
           for n, s in cat.items()}
    save(cat, path)
    return cat


def remove_subdomain(name: str, path: str | None = None) -> dict:
    """Remove a sub-domain and persist; return the updated catalog."""
    cat = load(path)
    cat.pop(name, None)
    save(cat, path)
    return cat

