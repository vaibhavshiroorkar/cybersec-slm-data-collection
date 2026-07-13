"""Offline tests for the persistent, editable keyword catalog."""

from cybersec_slm.sourcing import catalog
from cybersec_slm.sourcing import keywords as kw


def test_load_falls_back_to_builtin_defaults(tmp_path):
    # No file on disk -> the built-in keyword lists are used.
    cat = catalog.load(str(tmp_path / "missing.yaml"))
    assert set(cat) == set(kw.DOMAIN_KEYWORDS)
    for name, spec in cat.items():
        assert spec["datasets"] == kw.DOMAIN_KEYWORDS[name]


def test_save_load_round_trip(tmp_path):
    p = str(tmp_path / "keywords.yaml")
    cat = {"My Domain": {"datasets": ["a dataset", "b dataset"], "text": ["c guide"]}}
    catalog.save(cat, p)
    back = catalog.load(p)
    assert back == cat


def test_add_and_remove_subdomain(tmp_path):
    p = str(tmp_path / "keywords.yaml")
    catalog.save({"Keep": {"datasets": ["x"], "text": []}}, p)

    catalog.add_subdomain("New", datasets=["one", "two"], text=["three"], path=p)
    cat = catalog.load(p)
    assert catalog.subdomains(cat) == ["Keep", "New"]
    assert catalog.keywords_for("New", "both", cat) == ["one", "two", "three"]

    catalog.remove_subdomain("Keep", path=p)
    assert catalog.subdomains(catalog.load(p)) == ["New"]


def test_keyword_sets_pairs_modes_with_qualifiers(tmp_path):
    p = str(tmp_path / "keywords.yaml")
    catalog.save({"D": {"datasets": ["ds"], "text": ["tx"]}}, p)
    cat = catalog.load(p)

    ds_sets = catalog.keyword_sets("datasets", cat)
    assert ds_sets == [({"D": ["ds"]}, kw.QUERY_QUALIFIER)]

    both = catalog.keyword_sets("both", cat)
    assert [q for _, q in both] == [kw.QUERY_QUALIFIER, kw.TEXT_QUERY_QUALIFIER]


def test_normalize_drops_blank_keywords(tmp_path):
    p = str(tmp_path / "keywords.yaml")
    catalog.save({"D": {"datasets": ["  ", "kept", ""], "text": None}}, p)
    cat = catalog.load(p)
    assert cat["D"]["datasets"] == ["kept"]
    assert cat["D"]["text"] == []
