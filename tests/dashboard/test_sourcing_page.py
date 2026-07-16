"""Streamlit render tests for the Sourcing page's editing flows.

Drives the real page headlessly with AppTest: applying a sub-domain selection,
editing/renaming a sub-domain, and adding a source by hand. Skips unless the
`dashboard` extra is installed.
"""

import os

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_PAGE = os.path.join(_REPO, "src", "cybersec_slm", "dashboard", "pages",
                     "1_Sourcing.py")


@pytest.fixture
def page(tmp_path, monkeypatch):
    """The Sourcing page, fully isolated to tmp_path.

    ``data._repo_root`` resolves Sources.csv relative to the *package*, not the
    data root, so without patching it a test that clicks "Add source" would append
    to the real repo's sources/Sources.csv.
    """
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    from cybersec_slm.dashboard import data

    monkeypatch.setattr(data, "_repo_root", lambda: str(tmp_path))
    from cybersec_slm.sourcing import profiles
    profiles.ensure()
    return AppTest.from_file(_PAGE, default_timeout=30)


@pytest.fixture
def catalog_csv(tmp_path, monkeypatch):
    """The active profile's Sources.csv under the tmp data root."""
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    from cybersec_slm.sourcing import profiles
    return profiles.catalog_path()


def _taxonomy(**subdomains):
    from cybersec_slm.sourcing import catalog

    catalog.save({name: {"datasets": spec.get("datasets", []),
                         "text": spec.get("text", []),
                         "code": spec.get("code", ""),
                         "vocab": spec.get("vocab", [])}
                  for name, spec in subdomains.items()})


# ------------------------------------------------------------------- Apply ----
def test_apply_saves_the_selected_subdomains_and_mode(page):
    from cybersec_slm.dashboard import settings_store

    _taxonomy(**{"Cloud Security": {"datasets": ["cloud ds"]},
                 "Network Security": {"datasets": ["net ds"]}})

    page.run()
    assert not page.exception
    page.multiselect(key="src_domains").set_value(["Cloud Security"])
    page.selectbox(key="src_mode").set_value("text").run()
    page.button(key="src_apply").click().run()
    assert not page.exception

    saved = settings_store.get_stage("source")
    assert saved["domains"] == ["Cloud Security"]
    assert saved["mode"] == "text"


def test_apply_merges_into_the_existing_source_settings(page):
    """Applying a selection must not wipe the caps configured in the Overview
    page's Sourcing modal."""
    from cybersec_slm.dashboard import settings_store

    _taxonomy(**{"Cloud Security": {"datasets": ["c"]},
                 "Network Security": {"datasets": ["n"]}})
    settings_store.save_stage("source", {"per_keyword": 7, "max_minutes": 30.0,
                                         "domains": ["Network Security"]})

    page.run()
    page.multiselect(key="src_domains").set_value(["Cloud Security"])
    page.button(key="src_apply").click().run()
    assert not page.exception

    saved = settings_store.get_stage("source")
    assert saved["domains"] == ["Cloud Security"]     # replaced
    assert saved["per_keyword"] == 7                  # preserved
    assert saved["max_minutes"] == 30.0               # preserved


def test_apply_with_every_subdomain_selected_clears_the_restriction(page):
    """All selected == no restriction, so a sub-domain added later is searched too
    rather than being frozen out by a stale list."""
    from cybersec_slm.dashboard import settings_store

    _taxonomy(**{"Cloud Security": {"datasets": ["c"]},
                 "Network Security": {"datasets": ["n"]}})
    settings_store.save_stage("source", {"domains": ["Cloud Security"]})

    page.run()
    page.multiselect(key="src_domains").set_value(
        ["Cloud Security", "Network Security"])
    page.button(key="src_apply").click().run()
    assert not page.exception
    assert "domains" not in settings_store.get_stage("source")


# --------------------------------------------------------- edit a sub-domain --
def test_edit_renames_a_subdomain_and_relabels_its_catalog_rows(page, catalog_csv):
    from cybersec_slm.sourcing import catalog

    _taxonomy(**{"Cloud Security": {"datasets": ["cloud ds"], "text": ["cloud tx"],
                                    "code": "CLOUD", "vocab": ["s3"]}})
    with open(catalog_csv, "w", encoding="utf-8") as f:
        f.write("Name,Sub-Domain,Dataset Link,License\n"
                "A,Cloud Security,https://a.test/x,MIT\n"
                "B,Cloud Security,https://b.test/y,MIT\n")

    page.run()
    assert not page.exception
    page.text_input(key="ed_name_Cloud Security").set_value("Cloud & Platform")
    page.button(key="ed_save_Cloud Security").click().run()
    assert not page.exception

    cat = catalog.load()
    assert "Cloud Security" not in cat
    assert cat["Cloud & Platform"]["code"] == "CLOUD"      # code survives a rename
    assert cat["Cloud & Platform"]["datasets"] == ["cloud ds"]
    assert cat["Cloud & Platform"]["vocab"] == ["s3"]

    import pandas as pd
    df = pd.read_csv(catalog_csv, dtype=str, keep_default_na=False)
    assert list(df["Sub-Domain"]) == ["Cloud & Platform", "Cloud & Platform"]


def test_edit_rewrites_keywords_without_renaming(page):
    from cybersec_slm.sourcing import catalog

    _taxonomy(**{"Cloud Security": {"datasets": ["old"], "code": "CLOUD"}})

    page.run()
    page.text_area(key="ed_ds_Cloud Security").set_value("first kw\nsecond kw\n\n")
    page.button(key="ed_save_Cloud Security").click().run()
    assert not page.exception
    cat = catalog.load()
    assert cat["Cloud Security"]["datasets"] == ["first kw", "second kw"]
    assert cat["Cloud Security"]["code"] == "CLOUD"


def test_edit_rejects_a_rename_onto_an_existing_subdomain(page):
    from cybersec_slm.sourcing import catalog

    _taxonomy(**{"Cloud Security": {"datasets": ["c"]},
                 "Network Security": {"datasets": ["n"]}})

    page.run()
    page.text_input(key="ed_name_Cloud Security").set_value("Network Security").run()
    assert not page.exception
    assert any("already exists" in e.value for e in page.error)
    assert page.button(key="ed_save_Cloud Security").disabled
    # The collision target is untouched.
    assert catalog.load()["Network Security"]["datasets"] == ["n"]


# ------------------------------------------------------- add a source by hand --
def test_add_source_appends_a_row_to_the_catalog(page, catalog_csv):
    _taxonomy(**{"Cloud Security": {"datasets": ["c"]}})

    page.run()
    assert not page.exception
    page.text_input(key="ms_name").set_value("darkknight25")
    page.text_input(key="ms_link").set_value(
        "https://huggingface.co/datasets/dk/cloud")
    page.text_input(key="ms_lic").set_value("MIT")
    page.text_area(key="ms_desc").set_value("Cloud vulnerabilities").run()
    page.button(key="ms_add").click().run()
    assert not page.exception

    import pandas as pd
    df = pd.read_csv(catalog_csv, dtype=str, keep_default_na=False)
    # The active profile seeds its own-content rows, so assert on the row this
    # test added rather than on the catalog's total length.
    df = df[df["Name"] == "darkknight25"].reset_index(drop=True)
    assert len(df) == 1
    row = df.iloc[0]
    assert row["Name"] == "darkknight25"
    assert row["Sub-Domain"] == "Cloud Security"
    assert row["Dataset Link"] == "https://huggingface.co/datasets/dk/cloud"
    assert row["License"] == "MIT"
    assert row["Description"] == "Cloud vulnerabilities"
    assert row["Category"] == "Dataset"        # inferred from the HuggingFace link
    assert row["Date Added"]                   # auto-filled


def test_add_source_is_ingestable(page, catalog_csv):
    """The hand-added row must map to a source descriptor, or ingestion would
    silently never fetch it."""
    from cybersec_slm.ingestion import sources as srcs

    _taxonomy(**{"Cloud Security": {"datasets": ["c"]}})
    page.run()
    page.text_input(key="ms_name").set_value("darkknight25")
    page.text_input(key="ms_link").set_value(
        "https://huggingface.co/datasets/dk/cloud")
    page.text_input(key="ms_lic").set_value("MIT").run()
    page.button(key="ms_add").click().run()
    assert not page.exception

    # The profile's seeded own-content rows load too; pick out the one added here.
    descs = [d for d in srcs.load_descriptors(catalog_csv, order_by_size=False)
             if d.get("ref") == "dk/cloud"]
    assert len(descs) == 1
    assert descs[0]["kind"] == "hf"
    assert descs[0]["domain"] == "Cloud Security"
    assert descs[0]["license"] == "MIT"


def test_add_source_requires_name_and_link(page):
    _taxonomy(**{"Cloud Security": {"datasets": ["c"]}})
    page.run()
    assert page.button(key="ms_add").disabled       # nothing filled in yet
    page.text_input(key="ms_name").set_value("only a name").run()
    assert page.button(key="ms_add").disabled       # still no link


def test_add_source_refuses_a_link_already_in_the_catalog(page, catalog_csv):
    _taxonomy(**{"Cloud Security": {"datasets": ["c"]}})
    with open(catalog_csv, "w", encoding="utf-8") as f:
        f.write("Name,Sub-Domain,Dataset Link,License\n"
                "A,Cloud Security,https://huggingface.co/datasets/dk/cloud,MIT\n")

    page.run()
    page.text_input(key="ms_name").set_value("dupe")
    # The same source linked slightly differently is still recognized as present.
    page.text_input(key="ms_link").set_value(
        "http://www.huggingface.co/datasets/dk/cloud/").run()
    assert not page.exception
    assert any("already in the catalog" in w.value for w in page.warning)
    assert page.button(key="ms_add").disabled
