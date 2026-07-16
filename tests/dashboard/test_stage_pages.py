"""Streamlit render tests for the Ingest and Clean inspection pages.

The pages are the deliverable here, so these assert on what actually reaches the
screen (the per-source tables and the cleaning counters), not merely that the
script ran. Skips unless the `dashboard` extra is installed.
"""

import os

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_PAGES = os.path.join(_REPO, "src", "cybersec_slm", "dashboard", "pages")

_CLEAN_REPORT = (
    "sub_domain,source,file,in,mapped_text,excluded_no_text,sanitized,struct_fixed,"
    "struct_dropped,behavioral_flagged,exact_dups,near_dups,pii_redacted,translated,"
    "non_en_dropped,out\n"
    "Cloud Security,ownerA,a.jsonl,100,10,5,20,2,8,3,4,1,12,6,2,77\n"
    "Network Security,ownerC,c.jsonl,50,0,0,5,0,10,0,5,0,3,0,5,30\n"
    "TOTAL,,2 files,150,10,5,25,2,18,3,9,1,15,6,7,107\n"
)


def _dataframes(at):
    """Every rendered dataframe as a list of column->values dicts."""
    return [df.value for df in at.dataframe]


def _all_text(at):
    return " ".join([str(m.value) for m in at.markdown]
                    + [str(c.value) for c in at.caption])


@pytest.fixture
def clean_page(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    from cybersec_slm.dashboard import cached

    cached.clear_stats()
    logs = tmp_path / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "clean_report.csv").write_text(_CLEAN_REPORT, encoding="utf-8")
    return AppTest.from_file(os.path.join(_PAGES, "3_Clean.py"), default_timeout=30)


def test_clean_page_shows_the_pii_and_other_counters(clean_page):
    clean_page.run()
    assert not clean_page.exception

    metrics = {m.label: m.value for m in clean_page.metric}
    assert metrics["PII redacted"] == "15"
    assert metrics["Records in"] == "150"
    assert metrics["Records out"] == "107"
    assert metrics["Kept"] == "71.3%"


def test_clean_page_explains_every_mechanism_in_a_table(clean_page):
    clean_page.run()
    assert not clean_page.exception

    from cybersec_slm.dashboard import data

    detail = next(df for df in _dataframes(clean_page)
                  if "what it means" in df.columns)
    stages = list(detail["stage"])
    # Every counter except the in/out headline is explained on its own row.
    expected = [label for col, label, _h in data.CLEAN_COUNTERS
                if col not in ("in", "out")]
    assert stages == expected
    assert dict(zip(detail["stage"], detail["records"],
                    strict=True))["PII redacted"] == 15
    # The meaning is on the row, not hidden behind the CSV's column name.
    assert any("placeholder" in str(v) for v in detail["what it means"])


def test_clean_page_per_source_table_has_each_mechanism(clean_page):
    clean_page.run()
    assert not clean_page.exception

    per_source = next(df for df in _dataframes(clean_page)
                      if "pii" in df.columns and "kept %" in df.columns)
    rows = {r["source"]: r for _, r in per_source.iterrows()}
    assert set(rows) == {"ownerA", "ownerC"}
    assert rows["ownerA"]["in"] == 100
    assert rows["ownerA"]["out"] == 77
    assert rows["ownerA"]["pii"] == 12
    assert rows["ownerA"]["exact dups"] == 4
    assert rows["ownerC"]["non-en dropped"] == 5


def test_clean_page_says_so_when_no_clean_run_has_happened(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    from cybersec_slm.dashboard import cached

    cached.clear_stats()
    at = AppTest.from_file(os.path.join(_PAGES, "3_Clean.py"), default_timeout=30)
    at.run()
    assert not at.exception
    # No wall of zeros: the page explains there is nothing to show yet.
    assert "PII redacted" not in {m.label for m in at.metric}
    assert "no `logs/clean_report.csv` yet" in _all_text(at).lower()


@pytest.fixture
def ingest_page(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    from cybersec_slm.dashboard import cached, data
    from cybersec_slm.ingestion import license_gate
    from cybersec_slm.ingestion import sources as srcs

    cached.clear_stats()
    descs = [
        {"kind": "hf", "ref": "ownerA/ds", "domain": "Cloud Security",
         "url": "https://huggingface.co/datasets/ownerA/ds", "license": "MIT"},
        {"kind": "kaggle", "ref": "ownerB/ds", "domain": "Cryptography",
         "url": "https://kaggle.com/datasets/ownerB/ds", "license": "CC BY-NC"},
    ]
    monkeypatch.setattr(srcs, "load_descriptors", lambda *a, **k: descs)
    monkeypatch.setattr(license_gate, "is_license_ok",
                        lambda d: (False, "non-commercial (nc)")
                        if (d.get("ref") or "").startswith("ownerB") else (True, "ok"))

    catalog = tmp_path / "sources" / "Sources.csv"
    catalog.parent.mkdir(parents=True, exist_ok=True)
    catalog.write_text(
        "Name,Sub-Domain,Dataset Link,Total Lines,JSONL Size (MB),License\n"
        "Owner A,Cloud Security,https://huggingface.co/datasets/ownerA/ds,500,12.5,MIT\n"
        "Owner B,Cryptography,https://kaggle.com/datasets/ownerB/ds,900,3.0,CC BY-NC\n",
        encoding="utf-8")
    monkeypatch.setattr(data, "_repo_root", lambda: str(tmp_path))

    raw = tmp_path / "data" / "raw" / "Cloud Security" / "ownerA"
    raw.mkdir(parents=True)
    (raw / "f.jsonl").write_text('{"text": "x"}\n', encoding="utf-8")
    return AppTest.from_file(os.path.join(_PAGES, "2_Ingest.py"), default_timeout=30)


def test_ingest_page_shows_every_source_with_its_status(ingest_page):
    ingest_page.run()
    assert not ingest_page.exception

    table = next(df for df in _dataframes(ingest_page)
                 if "status" in df.columns and "license" in df.columns)
    rows = {r["source"]: r for _, r in table.iterrows()}
    assert set(rows) == {"ownerA", "ownerB"}

    assert rows["ownerA"]["status"] == "ingested"
    assert rows["ownerA"]["name"] == "Owner A"
    assert rows["ownerA"]["records"] == 500
    assert rows["ownerA"]["files"] == 1
    assert rows["ownerA"]["license"] == "MIT"

    assert rows["ownerB"]["status"] == "license"
    assert rows["ownerB"]["reason"] == "non-commercial (nc)"
    assert rows["ownerB"]["records"] == 0        # never credited: nothing on disk

    metrics = {m.label: m.value for m in ingest_page.metric}
    assert metrics["Catalogued"] == "2"
    assert metrics["Ingested"] == "1"
    assert metrics["License-excluded"] == "1"


def test_ingest_page_filters_the_table_by_status(ingest_page):
    ingest_page.run()
    ingest_page.multiselect(key="ingest_status_filter").set_value(["license"]).run()
    assert not ingest_page.exception

    table = next(df for df in _dataframes(ingest_page)
                 if "status" in df.columns and "license" in df.columns)
    assert list(table["source"]) == ["ownerB"]


def test_ingest_page_filters_the_table_by_subdomain(ingest_page):
    ingest_page.run()
    ingest_page.multiselect(key="ingest_domain_filter").set_value(
        ["Cloud Security"]).run()
    assert not ingest_page.exception

    table = next(df for df in _dataframes(ingest_page)
                 if "status" in df.columns and "license" in df.columns)
    assert list(table["source"]) == ["ownerA"]
