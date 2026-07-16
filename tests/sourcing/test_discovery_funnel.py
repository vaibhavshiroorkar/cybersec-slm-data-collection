"""The funnel a real ``discover()`` run reports.

test_stats.py pins the tally in isolation; this pins that the discovery loop
actually *calls* it, on the real code path, with a mixed bag of results. The two
matter separately: a correct counter nobody increments still reports all zeros.
"""

from __future__ import annotations

import pytest

from cybersec_slm.sourcing import run
from cybersec_slm.sourcing.search import Result


@pytest.fixture(autouse=True)
def _ubi(tmp_path, monkeypatch):
    """Pin the ubi profile — it is the one with restricted hosts to count.

    (conftest.py redirects run.LOGS for every test in this package, so discover()
    writes its review CSV + summary under tmp_path rather than the real repo.)
    """
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "ubi")
    yield


class _NoEnrich:
    def __init__(self, **kw):
        pass

    def enrich(self, row):
        row["License"] = "MIT"
        return row


def _hits(*links) -> list[Result]:
    return [Result(title=f"T{i}", link=link, snippet="s")
            for i, link in enumerate(links)]


def test_funnel_counts_every_hit_into_exactly_one_bucket(tmp_path, monkeypatch):
    served = _hits(
        "https://huggingface.co/datasets/a/aml",     # keep -> candidate
        "https://rbi.org.in/master-direction.pdf",   # restricted host
        "https://www.rbi.org.in/circular.pdf",       # restricted host (www)
        "https://sebi.gov.in/legal/x.html",          # restricted host
        "https://youtube.com/watch?v=1",             # junk host
        "https://github.com/topics/aml",             # listing page
        "https://huggingface.co/datasets/a/aml",     # duplicate of #1
    )
    # Serve the batch once, then nothing (so the run terminates).
    calls = {"n": 0}

    def fake_search(*a, **k):
        calls["n"] += 1
        return served if calls["n"] == 1 else []

    monkeypatch.setattr(run, "searxng_search", fake_search)
    monkeypatch.setattr(run, "Enricher", _NoEnrich)

    summ = run.discover(str(tmp_path / "Sources.csv"), domains=["AML-KYC"],
                        per_keyword=10, max_total=5, enrich=True)

    f = summ["funnel"]
    assert f["found"] == 7
    assert f["dropped"]["restricted host"] == 3
    assert f["dropped"]["junk host"] == 1
    assert f["dropped"]["listing page"] == 1
    assert f["duplicates"] == 1
    assert f["candidates"] == 1
    # The whole point: nothing is lost between the buckets.
    assert f["unprocessed"] == 0     # this run drained its buffer
    assert f["found"] == (f["dropped_total"] + f["duplicates"]
                          + f["candidates"] + f["unprocessed"])


def test_funnel_names_the_restricted_hosts_that_cost_the_most(tmp_path, monkeypatch):
    served = _hits(
        "https://rbi.org.in/a.pdf", "https://rbi.org.in/b.pdf",
        "https://rbi.org.in/c.pdf", "https://sebi.gov.in/d.html",
        "https://huggingface.co/datasets/a/aml",
    )
    calls = {"n": 0}

    def fake_search(*a, **k):
        calls["n"] += 1
        return served if calls["n"] == 1 else []

    monkeypatch.setattr(run, "searxng_search", fake_search)
    monkeypatch.setattr(run, "Enricher", _NoEnrich)

    summ = run.discover(str(tmp_path / "Sources.csv"), domains=["AML-KYC"],
                        per_keyword=10, max_total=5, enrich=True)

    hosts = summ["funnel"]["restricted_by_host"]
    assert list(hosts.items()) == [("rbi.org.in", 3), ("sebi.gov.in", 1)]


def test_funnel_records_license_verdicts_of_candidates(tmp_path, monkeypatch):
    served = _hits("https://huggingface.co/datasets/a/one",
                   "https://huggingface.co/datasets/a/two",
                   "https://huggingface.co/datasets/a/three")
    calls = {"n": 0}

    def fake_search(*a, **k):
        calls["n"] += 1
        return served if calls["n"] == 1 else []

    licenses = {"one": "MIT", "two": "CC BY-NC 4.0", "three": ""}

    class _Enricher:
        def __init__(self, **kw):
            pass

        def enrich(self, row):
            key = row["Dataset Link"].rsplit("/", 1)[-1]
            row["License"] = licenses[key]
            return row

    monkeypatch.setattr(run, "searxng_search", fake_search)
    monkeypatch.setattr(run, "Enricher", _Enricher)

    summ = run.discover(str(tmp_path / "Sources.csv"), domains=["AML-KYC"],
                        per_keyword=10, max_total=5, enrich=True)

    lic = summ["funnel"]["license"]
    assert lic == {"ok": 1, "unknown": 1, "blocked": 1}
    assert sum(lic.values()) == summ["funnel"]["candidates"]


def test_cybersec_profile_bars_nothing_so_the_bucket_stays_empty(tmp_path,
                                                                 monkeypatch):
    """The restricted-host bucket is ubi-specific; under cybersec the same hit is
    a normal candidate, not a drop."""
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "cybersec")
    calls = {"n": 0}

    def fake_search(*a, **k):
        calls["n"] += 1
        return _hits("https://rbi.org.in/a.pdf") if calls["n"] == 1 else []

    monkeypatch.setattr(run, "searxng_search", fake_search)
    monkeypatch.setattr(run, "Enricher", _NoEnrich)

    dom = run.catalog.subdomains(run.catalog.load())[0]
    summ = run.discover(str(tmp_path / "Sources.csv"), domains=[dom],
                        per_keyword=10, max_total=5, enrich=True)

    assert summ["funnel"]["dropped"]["restricted host"] == 0
    assert summ["funnel"]["candidates"] == 1
