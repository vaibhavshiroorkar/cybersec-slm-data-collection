"""Offline tests for the persistent, editable keyword catalog."""

import pytest

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
    expected = {"My Domain": {**cat["My Domain"], "links": [], "code": "", "vocab": []}}
    assert back == expected


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


def test_default_catalog_has_codes_and_vocab_for_builtin_domains(tmp_path):
    cat = catalog.load(str(tmp_path / "missing.yaml"))
    for name in kw.DOMAINS:
        assert cat[name]["code"] == kw.DOMAIN_CODES[name]
        assert set(cat[name]["vocab"]) == kw.DOMAIN_VOCAB[name]


def test_pre_existing_yaml_without_code_still_gets_historical_codes(tmp_path):
    """A keywords.yaml written before ``code``/``vocab`` existed (just
    datasets/text, as every file on disk today looks) must still resolve a
    built-in domain's historical enum code and vocab, not a freshly-derived
    slug -- the downstream snorkel LabelModel contract depends on this."""
    p = str(tmp_path / "keywords.yaml")
    catalog.save({"AML-KYC": {"datasets": ["d"], "text": ["t"]}}, p)
    # Emulate a file saved before this migration by stripping the keys save()
    # would have added, matching a real pre-existing keywords.yaml on disk.
    import yaml
    with open(p, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    del raw["subdomains"]["AML-KYC"]["code"]
    del raw["subdomains"]["AML-KYC"]["vocab"]
    with open(p, "w", encoding="utf-8") as f:
        yaml.safe_dump(raw, f)

    cat = catalog.load(p)
    assert cat["AML-KYC"]["code"] == kw.DOMAIN_CODES["AML-KYC"]
    assert set(cat["AML-KYC"]["vocab"]) == kw.DOMAIN_VOCAB["AML-KYC"]


def test_code_for_derives_a_stable_slug_when_unset(tmp_path):
    p = str(tmp_path / "keywords.yaml")
    catalog.save({"My New Thing": {"datasets": [], "text": []}}, p)
    cat = catalog.load(p)
    assert cat["My New Thing"]["code"] == ""             # not persisted by load()
    assert catalog.code_for("My New Thing", cat) == "MY_NEW_THING"


def test_code_for_disambiguates_slug_collisions(tmp_path):
    p = str(tmp_path / "keywords.yaml")
    catalog.save({"A/B": {"datasets": [], "text": [], "code": "A_B"},
                 "A B": {"datasets": [], "text": []}}, p)
    cat = catalog.load(p)
    assert catalog.code_for("A B", cat) == "A_B_2"        # "A_B" already taken


def test_add_subdomain_derives_and_persists_a_code(tmp_path):
    p = str(tmp_path / "keywords.yaml")
    catalog.save({}, p)
    catalog.add_subdomain("Physical Security", path=p)
    cat = catalog.load(p)
    assert cat["Physical Security"]["code"] == "PHYSICAL_SECURITY"


def test_add_subdomain_accepts_an_explicit_code(tmp_path):
    p = str(tmp_path / "keywords.yaml")
    catalog.save({}, p)
    catalog.add_subdomain("Physical Security", code="PHYSSEC", path=p)
    cat = catalog.load(p)
    assert cat["Physical Security"]["code"] == "PHYSSEC"


def test_domain_name_defaults_to_the_builtin_when_unset(tmp_path):
    p = str(tmp_path / "keywords.yaml")
    assert catalog.domain_name(p) == kw.DEFAULT_DOMAIN_NAME == "BANKING_COMPLIANCE"


def test_set_domain_name_round_trips_and_preserves_subdomains(tmp_path):
    p = str(tmp_path / "keywords.yaml")
    catalog.save({"Keep": {"datasets": ["x"], "text": []}}, p)
    catalog.set_domain_name("MEDTECH", p)
    assert catalog.domain_name(p) == "MEDTECH"
    # set_domain_name must not disturb the subdomains it re-saves alongside.
    assert catalog.subdomains(catalog.load(p)) == ["Keep"]


def test_add_subdomain_preserves_the_saved_domain_name(tmp_path):
    p = str(tmp_path / "keywords.yaml")
    catalog.save({"Keep": {"datasets": ["x"], "text": []}}, p)
    catalog.set_domain_name("MEDTECH", p)
    catalog.add_subdomain("New", path=p)
    assert catalog.domain_name(p) == "MEDTECH"


# ------------------------------------------------------------ update/rename ---
def _seed_one(path: str) -> None:
    catalog.save({"Old Name": {"datasets": ["ds1", "ds2"], "text": ["tx1"],
                               "code": "OLD", "vocab": ["term"]},
                  "Other": {"datasets": ["o"], "text": [], "code": "OTHER"}}, path)


def test_update_subdomain_edits_keywords_without_renaming(tmp_path):
    p = str(tmp_path / "keywords.yaml")
    _seed_one(p)
    catalog.update_subdomain("Old Name", datasets=["new1"], text=["new2"], path=p)
    cat = catalog.load(p)
    assert cat["Old Name"]["datasets"] == ["new1"]
    assert cat["Old Name"]["text"] == ["new2"]
    assert cat["Old Name"]["code"] == "OLD"          # untouched
    assert cat["Old Name"]["vocab"] == ["term"]      # untouched


def test_update_subdomain_renames_and_keeps_the_existing_code(tmp_path):
    """A rename must not silently change the schema enum code: records already
    normalized under the old code would no longer match the taxonomy."""
    p = str(tmp_path / "keywords.yaml")
    _seed_one(p)
    catalog.update_subdomain("Old Name", name="New Name", path=p)
    cat = catalog.load(p)
    assert "Old Name" not in cat
    assert cat["New Name"]["code"] == "OLD"
    assert cat["New Name"]["datasets"] == ["ds1", "ds2"]
    assert cat["New Name"]["vocab"] == ["term"]


def test_update_subdomain_none_means_leave_alone(tmp_path):
    p = str(tmp_path / "keywords.yaml")
    _seed_one(p)
    catalog.update_subdomain("Old Name", path=p)          # no fields at all
    assert catalog.load(p)["Old Name"] == {
        "datasets": ["ds1", "ds2"], "text": ["tx1"], "links": [], "code": "OLD",
        "vocab": ["term"]}


def test_update_subdomain_explicit_code_wins_and_blank_rederives(tmp_path):
    p = str(tmp_path / "keywords.yaml")
    _seed_one(p)
    catalog.update_subdomain("Old Name", code="EXPLICIT", path=p)
    assert catalog.load(p)["Old Name"]["code"] == "EXPLICIT"

    catalog.update_subdomain("Old Name", name="Fresh Label", code="", path=p)
    assert catalog.load(p)["Fresh Label"]["code"] == "FRESH_LABEL"


def test_update_subdomain_rejects_a_rename_onto_an_existing_subdomain(tmp_path):
    p = str(tmp_path / "keywords.yaml")
    _seed_one(p)
    with pytest.raises(ValueError, match="already exists"):
        catalog.update_subdomain("Old Name", name="Other", path=p)
    assert catalog.load(p)["Other"]["datasets"] == ["o"]   # not clobbered


def test_update_subdomain_rejects_an_unknown_subdomain(tmp_path):
    p = str(tmp_path / "keywords.yaml")
    _seed_one(p)
    with pytest.raises(KeyError):
        catalog.update_subdomain("Nope", name="X", path=p)


def test_update_subdomain_renaming_to_itself_is_a_no_op(tmp_path):
    p = str(tmp_path / "keywords.yaml")
    _seed_one(p)
    catalog.update_subdomain("Old Name", name="Old Name", path=p)
    assert catalog.subdomains(catalog.load(p)) == ["Old Name", "Other"]


def test_update_subdomain_preserves_the_saved_domain_name(tmp_path):
    p = str(tmp_path / "keywords.yaml")
    _seed_one(p)
    catalog.set_domain_name("MEDTECH", p)
    catalog.update_subdomain("Old Name", name="New Name", path=p)
    assert catalog.domain_name(p) == "MEDTECH"

