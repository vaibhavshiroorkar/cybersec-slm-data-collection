"""Tests for the synthetic-source identity + catalog-flag lookup."""

from __future__ import annotations

import pandas as pd

from cybersec_slm.ingestion import sources
from cybersec_slm.ingestion.sources import source_identity, synthetic_identities


def test_identity_hf_bare_and_resolve_match():
    bare = "https://huggingface.co/datasets/ai4privacy/pii-masking-200k"
    resolve = ("https://huggingface.co/datasets/ai4privacy/pii-masking-200k/"
               "resolve/main/english_pii_43k.jsonl")
    assert source_identity(bare) == "hf:ai4privacy/pii-masking-200k"
    # the per-file resolve URL collapses to the same identity as the bare link
    assert source_identity(resolve) == source_identity(bare)


def test_identity_kaggle_lowercased_and_suffix_stripped():
    k = "https://www.kaggle.com/datasets/ZIYA07/Network-Security-Dataset/data"
    assert source_identity(k) == "kaggle:ziya07/network-security-dataset"


def test_identity_slug_collision_stays_distinct():
    # both share the folder slug 'darkknight25' but are different datasets
    a = source_identity("https://huggingface.co/datasets/darkknight25/Advanced_SIEM_Dataset")
    b = source_identity("https://huggingface.co/datasets/darkknight25/phishing_benign_email_dataset")
    assert a != b


def test_identity_non_dataset_and_empty():
    assert (source_identity("https://www.cisa.gov/known-exploited-vulnerabilities-catalog/")
            == "url:cisa.gov/known-exploited-vulnerabilities-catalog")
    assert source_identity("") is None
    assert source_identity(None) is None


def _catalog(tmp_path, rows):
    df = pd.DataFrame([{c: r.get(c, "") for c in sources.CATALOG_COLUMNS} for r in rows])
    p = tmp_path / "cat.csv"
    df.to_csv(p, index=False, encoding="utf-8")
    return str(p)


def test_synthetic_identities_reads_flag(tmp_path):
    cat = _catalog(tmp_path, [
        {"Name": "A", "Dataset Link": "https://huggingface.co/datasets/org/synth",
         "Is Synthetic?": "Yes"},
        {"Name": "B", "Dataset Link": "https://huggingface.co/datasets/org/real",
         "Is Synthetic?": ""},
        {"Name": "C", "Dataset Link": "https://www.kaggle.com/datasets/u/sim",
         "Is Synthetic?": "yes"},   # case-insensitive truthy
    ])
    assert synthetic_identities(cat) == frozenset({"hf:org/synth", "kaggle:u/sim"})


def test_synthetic_identities_of_a_missing_catalog_is_empty_not_an_error(tmp_path):
    """Normalize runs over data/clean, which can exist without the catalog (a
    corpus handed over without its sourcing sheet, an isolated test root). A
    missing catalog means nothing is flagged synthetic, so the stage keeps running
    rather than failing over a filter with nothing to filter."""
    assert synthetic_identities(str(tmp_path / "nope" / "Sources.csv")) == frozenset()

