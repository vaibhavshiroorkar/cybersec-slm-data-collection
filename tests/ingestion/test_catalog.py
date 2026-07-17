"""Catalog loader tests — Sources.csv -> descriptors (no network)."""

from __future__ import annotations

import pandas as pd

from cybersec_slm.ingestion import sources

# Header subset that exercises every dispatch branch, including the two
# infrastructure kinds (api/xml) auto-detected by URL.
_ROWS = [
    # Name, Sub-Domain, Dataset Link, Category, Original Format
    ("hf-ds", "Application Security",
     "https://huggingface.co/datasets/foo/bar", "Dataset", "JSON"),
    ("kaggle-ds", "Cloud Security",
     "https://www.kaggle.com/datasets/foo/bar", "Dataset", "CSV"),
    ("gh-ds", "Network Security",
     "https://github.com/foo/bar", "Repository", "CSV"),
    ("a-pdf", "Cryptography",
     "https://example.gov/doc.pdf", "Document", "PDF"),
    ("a-feed", "Threat Intelligence",
     "https://example.com/data.json", "Feed", "JSON"),
    ("nvd", "Vulnerability Management",
     "https://services.nvd.nist.gov/rest/json/cves/2.0", "API", "JSON"),
    ("cwe", "Vulnerability Management",
     "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip", "Feed", "XML"),
]


def _write_catalog(path) -> str:
    cols = ["Name", "Sub-Domain", "Dataset Link", "Category", "Original Format"]
    df = pd.DataFrame(_ROWS, columns=cols)
    p = str(path / "Sources.csv")
    df.to_csv(p, index=False, encoding="utf-8")
    return p


def test_load_descriptors_maps_every_kind(tmp_path):
    descriptors = sources.load_descriptors(_write_catalog(tmp_path))
    by_kind = {d["kind"] for d in descriptors}
    assert {"hf", "kaggle", "github", "pdf", "feed", "api", "xml"} <= by_kind
    assert len(descriptors) == len(_ROWS)
    assert all("domain" in d for d in descriptors)


def test_nvd_and_cwe_detected_by_url(tmp_path):
    descriptors = sources.load_descriptors(_write_catalog(tmp_path))
    by_url = {d.get("url"): d for d in descriptors}
    nvd = by_url["https://services.nvd.nist.gov/rest/json/cves/2.0"]
    cwe = by_url["https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"]
    assert nvd["kind"] == "api" and nvd["slug"] and nvd["title"]
    assert cwe["kind"] == "xml" and cwe["slug"] and cwe["title"]


def test_real_catalog_loads_with_infra_sources(monkeypatch):
    # The committed catalog must load and include the NVD + CWE rows. Those rows
    # live in the cybersec profile; the ubi profile ships an empty catalog that
    # sourcing fills, so pin the profile rather than reading whichever is active.
    #
    # This is the one test that wants the real checkout: the suite's root conftest
    # pins the data root to a temp directory so no test can touch a developer's
    # corpus, and reading the committed catalog means opting back out of that. It
    # only reads.
    import os
    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", repo)
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "cybersec")
    descriptors = sources.load_descriptors(sources.default_catalog())
    kinds = {d["kind"] for d in descriptors}
    assert len(descriptors) > 0
    assert {"api", "xml"} <= kinds
