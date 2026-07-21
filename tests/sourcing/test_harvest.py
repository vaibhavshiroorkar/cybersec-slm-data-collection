"""Offline tests for the bulk-harvest backends + driver.

No network: the CKAN ``_fetch_page`` is monkeypatched to return a fixed payload,
so the row-mapping, quality pre-filter, pagination, and the driver's dedup /
target / dry-run logic are all exercised against deterministic data.
"""

from __future__ import annotations

import csv

import pytest

from cybersec_slm.sourcing.harvest import ckan
from cybersec_slm.sourcing.harvest import run as harvest_run
from cybersec_slm.sourcing.harvest import spec as harvest_spec
from cybersec_slm.sourcing.row import SHEET_COLUMNS


# A minimal CKAN package_search payload shape: result.results is a list of
# packages, each with title/notes and a resources list. The first package hits
# the AML-KYC query keyword; the second is off-topic (COVID) and should be
# quality-dropped; the third has a too-short title.
def _payload(packages, count=None):
    return {"result": {"count": count if count is not None else len(packages),
                       "results": packages}}


def _pkg(title, notes, slug, fmt="CSV", data_url="https://x/data.csv"):
    return {"title": title, "notes": notes,
            "resources": [{"name": slug, "id": "uuid-" + slug,
                           "format": fmt, "url": data_url}]}


_UBI_SPEC = {
    "name": "ckan",
    "base_url": "https://www.data.gov.in",
    "api_key_env": "DATAGOVINDIA_API_KEY",
    "action": "package_search",
    "rows_per_page": 100,
    "license": "Government Open Data License - India (GODL)",
    "country": "India",
    "field": "Finance",
    "quality": {"require_title_min_chars": 8, "require_any_keyword": True},
    "per_domain_queries": {
        "AML-KYC": ["fraud", "money laundering"],
    },
}


# ----------------------------------------------------------------- mapping ---


def test_map_package_stamps_godl_and_india(monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "ubi")
    pkg = _pkg("Year-wise frauds reported by banks",
               "Number of frauds reported by commercial banks",
               "year-wise-frauds-banks")
    row = ckan._map_package(pkg, _UBI_SPEC, "AML-KYC", "19/07/2026", None,
                            ["fraud", "money laundering"])
    assert row is not None
    assert row["License"] == "Government Open Data License - India (GODL)"
    assert row["Country"] == "India"
    assert row["Field"] == "Finance"
    assert row["Category"] == "Dataset"
    assert row["Dataset Link"] == "https://www.data.gov.in/resource/year-wise-frauds-banks"
    assert row["Date Added"] == "19/07/2026"
    assert set(row) == set(SHEET_COLUMNS)


def test_map_package_drops_off_topic():
    # COVID positivity — no fraud/money-laundering keyword -> quality-dropped.
    pkg = _pkg("COVID-19 district-wise positivity rate",
               "Daily RT-PCR monitoring report", "covid-positivity-23022022")
    row = ckan._map_package(pkg, _UBI_SPEC, "AML-KYC", "19/07/2026", None,
                            ["fraud", "money laundering"])
    assert row is None


def test_map_package_drops_short_title():
    pkg = _pkg("Fraud", "Short title under min chars", "fraud")
    row = ckan._map_package(pkg, _UBI_SPEC, "AML-KYC", "19/07/2026", None,
                            ["fraud", "money laundering"])
    assert row is None


def test_map_package_drops_resourceless():
    pkg = {"title": "Frauds reported by banks over the years", "notes": "n",
           "resources": []}
    row = ckan._map_package(pkg, _UBI_SPEC, "AML-KYC", "19/07/2026", None,
                            ["fraud", "money laundering"])
    assert row is None


# ------------------------------------------------------------- pagination ---


def test_harvest_paginates_until_exhausted(monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "ubi")
    spec = dict(_UBI_SPEC)
    spec["rows_per_page"] = 3            # so 6 results span 2 pages
    # One query only, so the fake_fetch pages are consumed linearly by it.
    spec["per_domain_queries"] = {"AML-KYC": ["fraud"]}
    pages = [
        _payload([_pkg(f"Frauds in banking year {i}",
                       "money laundering dataset " * 5, f"fraud-{i}")
                  for i in range(3)], count=6),
        _payload([_pkg(f"Frauds in banking year {i}",
                       "money laundering dataset " * 5, f"fraud-{i}")
                  for i in range(3, 6)], count=6),
        _payload([], count=6),
    ]
    calls = {"i": 0}

    def fake_fetch(url, params, headers, *, client=None, owns=False):
        p = pages[min(calls["i"], len(pages) - 1)]
        calls["i"] += 1
        return p

    monkeypatch.setattr(ckan, "_fetch_page", fake_fetch)
    rows = list(ckan.harvest(spec))
    assert len(rows) == 6
    assert all(r["License"].startswith("Government Open Data") for r in rows)
    # Two pages of 3 fill the count of 6 (start reaches total -> stops).
    assert calls["i"] == 2


def test_harvest_respects_max_results(monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "ubi")
    spec = dict(_UBI_SPEC)
    spec["max_results"] = 2

    def fake_fetch(url, params, headers, *, client=None, owns=False):
        return _payload([_pkg(f"Frauds in banking year {i}",
                              "money laundering " * 10, f"fraud-{i}")
                         for i in range(5)], count=100)

    monkeypatch.setattr(ckan, "_fetch_page", fake_fetch)
    rows = list(ckan.harvest(spec))
    assert len(rows) == 2


def test_harvest_raises_on_403(monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "ubi")

    def fake_fetch(url, params, headers, *, client=None, owns=False):
        raise ckan.HarvestError("HTTP 403")

    monkeypatch.setattr(ckan, "_fetch_page", fake_fetch)
    with pytest.raises(ckan.HarvestError):
        list(ckan.harvest(_UBI_SPEC))


# --------------------------------------------------------------- backend ---


def test_registry_resolves_ckan():
    from cybersec_slm.sourcing.harvest import base
    backend = base.get("ckan")
    assert hasattr(backend, "harvest")


def test_registry_unknown_raises():
    from cybersec_slm.sourcing.harvest import base
    with pytest.raises(KeyError):
        base.get("nope")


# ------------------------------------------------------------------ spec ---


def test_spec_load_falls_back_to_taxonomy_default(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "ubi")
    # Force re-seed so harvest.yaml is written from the taxonomy default.
    from cybersec_slm.sourcing import profiles
    profiles.ensure("ubi")
    loaded = harvest_spec.load("ubi")
    assert loaded["target_total"] == 10000
    assert loaded["backends"][0]["name"] == "ckan"
    assert loaded["backends"][0]["base_url"] == "https://www.data.gov.in"


def test_spec_no_harvest_for_cybersec(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    from cybersec_slm.sourcing import profiles
    profiles.ensure("cybersec")
    loaded = harvest_spec.load("cybersec")
    assert loaded == {}


# --------------------------------------------------------------- driver ---


def _write_catalog(path, links):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(list(SHEET_COLUMNS))
        for ln in links:
            w.writerow(["x", "AML-KYC", "Finance", "India", "d", ln]
                       + [""] * (len(SHEET_COLUMNS) - 6))


def test_driver_appends_and_dedups(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "ubi")
    from cybersec_slm.sourcing import profiles
    profiles.ensure("ubi")
    csv_path = profiles.catalog_path("ubi")
    # Pre-seed one existing row so dedup is exercised.
    _write_catalog(csv_path, ["https://www.data.gov.in/resource/fraud-0"])

    # Backend yields 3 rows, one of which collides with the existing link.
    def fake_harvest(spec, *, client=None):
        for i in range(3):
            yield {c: "" for c in SHEET_COLUMNS} | {
                "Name": f"Frauds in banking year {i}",
                "Sub-Domain": "AML-KYC",
                "Dataset Link": f"https://www.data.gov.in/resource/fraud-{i}",
                "License": "Government Open Data License - India (GODL)",
                "Country": "India", "Field": "Finance",
                "Category": "Dataset", "Date Added": "19/07/2026",
            }

    class _FakeBackend:
        def harvest(self, spec, *, client=None):
            return fake_harvest(spec, client=client)

    from cybersec_slm.sourcing.harvest import base
    base.register("ckan", _FakeBackend())

    summary = harvest_run.run_harvest("ubi", target_total=10)
    # fraud-0 deduped; fraud-1 and fraud-2 appended.
    assert summary["appended"] == 2
    assert summary["duplicates"] == 1


def test_driver_dry_run_writes_nothing(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "ubi")
    from cybersec_slm.sourcing import profiles
    profiles.ensure("ubi")
    csv_path = profiles.catalog_path("ubi")
    rows_before = sum(1 for _ in open(csv_path, encoding="utf-8"))

    class _FakeBackend:
        def harvest(self, spec, *, client=None):
            row = {c: "" for c in SHEET_COLUMNS}
            row.update({"Name": "Frauds in banking year 9",
                        "Sub-Domain": "AML-KYC",
                        "Dataset Link": "https://www.data.gov.in/resource/fraud-9",
                        "License": "GODL", "Country": "India",
                        "Field": "Finance", "Category": "Dataset",
                        "Date Added": "19/07/2026"})
            yield row

    from cybersec_slm.sourcing.harvest import base
    base.register("ckan", _FakeBackend())
    summary = harvest_run.run_harvest("ubi", dry_run=True, target_total=10)
    assert summary["appended"] == 0
    assert summary["dry_run"] is True
    rows_after = sum(1 for _ in open(csv_path, encoding="utf-8"))
    assert rows_after == rows_before      # catalog untouched


def test_driver_target_stops_early(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "ubi")
    from cybersec_slm.sourcing import profiles
    profiles.ensure("ubi")

    class _FakeBackend:
        def harvest(self, spec, *, client=None):
            for i in range(50):
                row = {c: "" for c in SHEET_COLUMNS}
                row.update({"Name": f"Frauds in banking year {i}",
                            "Sub-Domain": "AML-KYC",
                            "Dataset Link": f"https://www.data.gov.in/resource/fraud-t{i}",
                            "License": "GODL", "Country": "India",
                            "Field": "Finance", "Category": "Dataset",
                            "Date Added": "19/07/2026"})
                yield row

    from cybersec_slm.sourcing.harvest import base
    base.register("ckan", _FakeBackend())
    summary = harvest_run.run_harvest("ubi", target_total=5)
    assert summary["appended"] == 5
    assert summary["target_reached"] is True


def test_driver_idempotent_second_run(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "ubi")
    from cybersec_slm.sourcing import profiles
    profiles.ensure("ubi")

    class _FakeBackend:
        def harvest(self, spec, *, client=None):
            row = {c: "" for c in SHEET_COLUMNS}
            row.update({"Name": "Frauds in banking year 7",
                        "Sub-Domain": "AML-KYC",
                        "Dataset Link": "https://www.data.gov.in/resource/fraud-7",
                        "License": "GODL", "Country": "India",
                        "Field": "Finance", "Category": "Dataset",
                        "Date Added": "19/07/2026"})
            yield row

    from cybersec_slm.sourcing.harvest import base
    base.register("ckan", _FakeBackend())
    first = harvest_run.run_harvest("ubi", target_total=10)
    second = harvest_run.run_harvest("ubi", target_total=10)
    assert first["appended"] == 1
    assert second["appended"] == 0      # the row is now a duplicate
    assert second["duplicates"] >= 1
