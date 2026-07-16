"""A catalog row's Sub-Domain resolves against the live taxonomy, not a hardcoded map.

The pipeline is meant to generalize past cybersecurity: point ``keywords.yaml`` at
another data domain and a foreign CSV's coarse ``category`` column must resolve
against *that* taxonomy, never silently inject a cybersec sub-domain the taxonomy
does not define.
"""

from __future__ import annotations

import pytest

from cybersec_slm.ingestion import sources as srcs
from cybersec_slm.sourcing import catalog


@pytest.fixture(autouse=True)
def _clear_taxonomy_cache():
    """The lookup is cached on (path, mtime); tests rewrite it faster than that."""
    srcs._taxonomy_cache = None
    yield
    srcs._taxonomy_cache = None


def _use_taxonomy(tmp_path, monkeypatch, cat: dict) -> None:
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    catalog.save(cat, str(tmp_path / "sources" / "keywords.yaml"))
    srcs._taxonomy_cache = None


def test_explicit_subdomain_always_wins(tmp_path, monkeypatch):
    _use_taxonomy(tmp_path, monkeypatch,
                  {"Radiology": {"datasets": [], "text": [], "code": "RAD"}})
    assert srcs._domain_for({"sub_domain": "Anything At All",
                             "category": "malware"}) == "Anything At All"


def test_category_resolves_by_subdomain_name(tmp_path, monkeypatch):
    _use_taxonomy(tmp_path, monkeypatch,
                  {"Clinical Notes": {"datasets": [], "text": [], "code": "NOTES"}})
    for spelling in ("Clinical Notes", "clinical notes", "clinical_notes"):
        assert srcs._domain_for({"category": spelling}) == "Clinical Notes"


def test_category_resolves_by_schema_enum_code(tmp_path, monkeypatch):
    _use_taxonomy(tmp_path, monkeypatch,
                  {"Clinical Notes": {"datasets": [], "text": [], "code": "NOTES"}})
    assert srcs._domain_for({"category": "NOTES"}) == "Clinical Notes"
    assert srcs._domain_for({"category": "notes"}) == "Clinical Notes"


def test_legacy_hints_apply_only_when_the_taxonomy_defines_the_target(
        tmp_path, monkeypatch):
    """'malware' -> 'Threat Intelligence' is a cybersec hint. Under a medical
    taxonomy it must not fire: the row keeps its own category rather than being
    filed under a sub-domain that taxonomy never defined."""
    _use_taxonomy(tmp_path, monkeypatch,
                  {"Radiology": {"datasets": [], "text": [], "code": "RAD"}})
    assert srcs._domain_for({"category": "malware"}) == "malware"
    assert "Threat Intelligence" not in srcs._taxonomy_lookup().values()


def test_legacy_hints_still_map_under_the_cybersec_taxonomy(tmp_path, monkeypatch):
    """Every historical CATEGORY_TO_DOMAIN entry keeps working while the built-in
    cybersecurity taxonomy is the live one -- this generalization is not a
    behavior change for the existing catalog."""
    _use_taxonomy(tmp_path, monkeypatch, catalog._defaults())
    for category, expected in srcs.CATEGORY_TO_DOMAIN.items():
        assert srcs._domain_for({"category": category}) == expected


def test_unresolvable_category_is_kept_verbatim(tmp_path, monkeypatch):
    _use_taxonomy(tmp_path, monkeypatch,
                  {"Radiology": {"datasets": [], "text": [], "code": "RAD"}})
    assert srcs._domain_for({"category": "something novel"}) == "something novel"


def test_blank_row_is_uncategorized(tmp_path, monkeypatch):
    _use_taxonomy(tmp_path, monkeypatch,
                  {"Radiology": {"datasets": [], "text": [], "code": "RAD"}})
    assert srcs._domain_for({}) == "Uncategorized"
    assert srcs._domain_for({"category": "   "}) == "Uncategorized"


def test_taxonomy_lookup_is_cached_per_catalog_file(tmp_path, monkeypatch):
    _use_taxonomy(tmp_path, monkeypatch,
                  {"Radiology": {"datasets": [], "text": [], "code": "RAD"}})
    first = srcs._taxonomy_lookup()
    calls: list[int] = []
    real_load = catalog.load
    monkeypatch.setattr(catalog, "load",
                        lambda *a, **k: (calls.append(1), real_load(*a, **k))[1])
    assert srcs._taxonomy_lookup() == first
    assert not calls, "the taxonomy was re-read despite an unchanged catalog file"


def test_taxonomy_lookup_survives_an_unreadable_catalog(tmp_path, monkeypatch):
    """A broken keywords.yaml must not take ingestion down; the row keeps its
    own category text."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    p = tmp_path / "sources" / "keywords.yaml"
    p.parent.mkdir(parents=True)
    p.write_text("subdomains: [this is: not: a mapping\n", encoding="utf-8")
    srcs._taxonomy_cache = None
    assert srcs._taxonomy_lookup() == {}
    assert srcs._domain_for({"category": "malware"}) == "malware"
