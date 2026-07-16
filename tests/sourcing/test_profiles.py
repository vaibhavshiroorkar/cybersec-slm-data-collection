"""Profiles: switchable corpora, each with its own taxonomy and catalog.

The point of a profile is that switching it re-points *every* stage at once —
sourcing's keywords, the schema's sub-domain enum, and the catalog CSV. These
tests pin that, plus the isolation between profiles (one profile's edits must not
leak into another's) and the fallbacks that made the pre-profile code correct.
"""

from __future__ import annotations

import os

import pytest

from cybersec_slm.sourcing import catalog, profiles, taxonomies


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    """Every test gets its own data root, so nothing touches the repo's profiles."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    monkeypatch.delenv("CYBERSEC_SLM_PROFILE", raising=False)
    yield


# ---------------------------------------------------------------- resolution ---


def test_active_defaults_to_the_builtin_default():
    assert profiles.active() == taxonomies.DEFAULT_PROFILE == "ubi"


def test_env_var_overrides_the_default(monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "cybersec")
    assert profiles.active() == "cybersec"


def test_use_persists_across_processes():
    profiles.use("cybersec")
    assert profiles.active() == "cybersec"
    # The choice is a file, not process state — a fresh read sees it.
    with open(os.path.join(str(profiles._sources_root()), "active_profile"),
              encoding="utf-8") as f:
        assert f.read().strip() == "cybersec"


def test_env_var_beats_the_persisted_choice(monkeypatch):
    profiles.use("cybersec")
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "ubi")
    assert profiles.active() == "ubi", "env must win, for one-off runs"


def test_a_stale_pointer_degrades_to_the_default(monkeypatch):
    """A profile that was deleted out from under the pointer must not break every
    stage's import — active() falls back rather than raising."""
    os.makedirs(profiles._sources_root(), exist_ok=True)
    with open(os.path.join(profiles._sources_root(), "active_profile"), "w",
              encoding="utf-8") as f:
        f.write("deleted-profile\n")
    assert profiles.active() == taxonomies.DEFAULT_PROFILE


def test_stale_env_var_degrades_to_the_default(monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "nope")
    assert profiles.active() == taxonomies.DEFAULT_PROFILE


def test_use_rejects_an_unknown_profile():
    with pytest.raises(profiles.UnknownProfile):
        profiles.use("not-a-profile")


@pytest.mark.parametrize("bad", ["../escape", "a/b", "a\\b", "", "  ", ".hidden"])
def test_invalid_profile_names_are_rejected(bad):
    """The name becomes a directory, so a traversal must never resolve."""
    with pytest.raises(ValueError):
        profiles.validate_name(bad)


# ------------------------------------------------------------------ seeding ---


def test_ensure_seeds_a_builtin_from_its_taxonomy():
    profiles.ensure("ubi")
    cat = catalog.load(profiles.keywords_path("ubi"), profile="ubi")
    assert catalog.subdomains(cat) == [
        "AML-KYC", "Compliance and Risk Management",
        "Corporate Governance", "Internal Audit"]
    assert os.path.exists(profiles.catalog_path("ubi"))


def test_ensure_never_clobbers_an_existing_taxonomy():
    profiles.ensure("ubi")
    catalog.save({"Only Mine": {"datasets": ["x"], "text": [], "code": "MINE"}},
                 profiles.keywords_path("ubi"), domain_name="MINE")
    profiles.ensure("ubi")          # must be a no-op over the user's edit
    cat = catalog.load(profiles.keywords_path("ubi"), profile="ubi")
    assert catalog.subdomains(cat) == ["Only Mine"]


def test_ensure_is_idempotent_and_keeps_catalog_rows():
    profiles.ensure("ubi")
    with open(profiles.catalog_path("ubi"), "a", encoding="utf-8") as f:
        f.write("MySource,AML-KYC,desc,https://x.test/d,1,Dataset,CSV,,,,,,MIT\n")
    profiles.ensure("ubi")
    with open(profiles.catalog_path("ubi"), encoding="utf-8") as f:
        assert "MySource" in f.read(), "ensure() must not truncate a live catalog"


# ---------------------------------------------------------------- isolation ---


def test_each_profile_keeps_its_own_taxonomy_and_catalog():
    profiles.ensure("ubi")
    profiles.ensure("cybersec")
    assert profiles.keywords_path("ubi") != profiles.keywords_path("cybersec")

    ubi = catalog.subdomains(catalog.load(profiles.keywords_path("ubi"),
                                          profile="ubi"))
    cyber = catalog.subdomains(catalog.load(profiles.keywords_path("cybersec"),
                                            profile="cybersec"))
    assert "AML-KYC" in ubi and "AML-KYC" not in cyber
    assert "Threat Intelligence" in cyber and "Threat Intelligence" not in ubi


def test_editing_one_profile_leaves_the_other_alone():
    profiles.ensure("ubi")
    profiles.ensure("cybersec")
    catalog.add_subdomain("Brand New", path=profiles.keywords_path("ubi"))

    cyber = catalog.subdomains(catalog.load(profiles.keywords_path("cybersec"),
                                            profile="cybersec"))
    assert "Brand New" not in cyber


def test_a_profiles_codes_do_not_leak_from_the_active_one():
    """Reading cybersec's taxonomy while ubi is active must use *cybersec's*
    built-in enum codes. Defaulting to the active profile here would hand its
    sub-domains freshly-derived slugs and silently break the schema contract."""
    profiles.ensure("cybersec")
    assert profiles.active() == "ubi"
    cat = catalog.load(profiles.keywords_path("cybersec"), profile="cybersec")
    codes = tuple(catalog.code_for(n, cat) for n in catalog.subdomains(cat))
    assert codes[:3] == ("APPLICATION", "CLOUD", "CRYPTOGRAPHY")
    assert catalog.domain_name(profiles.keywords_path("cybersec"),
                               profile="cybersec") == "CYBERSEC"


def test_switching_profile_repoints_the_catalog_csv():
    before = profiles.catalog_path()
    profiles.use("cybersec")
    after = profiles.catalog_path()
    assert before != after
    assert after.endswith(os.path.join("cybersec", "Sources.csv"))


# ------------------------------------------------------------------- create ---


def test_create_makes_an_empty_profile():
    profiles.create("medtech", domain_name="MEDTECH")
    assert profiles.exists("medtech")
    assert catalog.domain_name(profiles.keywords_path("medtech"),
                               profile="medtech") == "MEDTECH"
    assert catalog.subdomains(
        catalog.load(profiles.keywords_path("medtech"), profile="medtech")) == []
    assert "medtech" in profiles.names()


def test_create_refuses_to_overwrite():
    profiles.create("medtech")
    with pytest.raises(FileExistsError):
        profiles.create("medtech")


def test_a_custom_profile_can_be_activated_and_used():
    profiles.create("medtech", domain_name="MEDTECH", use_it=True)
    assert profiles.active() == "medtech"
    catalog.add_subdomain("Radiology", datasets=["chest x-ray dataset"])
    assert catalog.subdomains() == ["Radiology"]


def test_info_reports_the_named_profile_not_the_active_one():
    profiles.ensure("cybersec")
    info = profiles.info("cybersec")
    assert info["name"] == "cybersec"
    assert info["active"] is False
    assert info["domain_name"] == "CYBERSEC"
    assert len(info["subdomains"]) == 12


# -------------------------------------------------------------- seed rows ----


def test_ubi_seeds_its_own_content_into_the_catalog():
    """UBI's own policies/disclosures ship as catalog rows, not search keywords:
    a search engine is the wrong tool for enumerating our own site, and every
    engine that honours `site:` rate-limits a sweep within a few queries."""
    profiles.ensure("ubi")
    import csv
    with open(profiles.catalog_path("ubi"), encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows, "the ubi profile must seed its own-content sources"
    assert all("unionbankofindia.bank.in" in r["Dataset Link"] for r in rows)
    # Every sub-domain the department named is covered.
    assert {r["Sub-Domain"] for r in rows} >= {
        "Compliance and Risk Management", "AML-KYC", "Corporate Governance"}


def test_seeded_own_content_passes_the_license_gate():
    """The authorization is inert unless the gate accepts it — these rows would
    otherwise be discovered and then silently blocked at ingestion."""
    from cybersec_slm.ingestion.license_gate import is_license_ok

    profiles.ensure("ubi")
    import csv
    with open(profiles.catalog_path("ubi"), encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        ok, why = is_license_ok({"license": r["License"]})
        assert ok, f"seeded own-content row blocked by the gate: {why}"


def test_seeding_never_overwrites_an_existing_catalog():
    profiles.ensure("ubi")
    path = profiles.catalog_path("ubi")
    with open(path, "w", encoding="utf-8") as f:
        f.write("Name,Sub-Domain\n")          # a user pruned it down
    profiles.ensure("ubi")
    with open(path, encoding="utf-8") as f:
        assert f.read().strip() == "Name,Sub-Domain", (
            "ensure() re-seeded rows the user had deleted")


def test_cybersec_seeds_nothing():
    profiles.ensure("cybersec")
    import csv
    with open(profiles.catalog_path("cybersec"), encoding="utf-8") as f:
        assert list(csv.DictReader(f)) == []
