"""The funnel a real engine run reports, on the live code path.

test_stats.py pins the tally in isolation; this pins that the orchestrator actually
*calls* it, with a mixed bag of candidates, so every hit lands in exactly one
bucket. A correct counter nobody increments still reports all zeros.
"""

from __future__ import annotations

import pytest

from cybersec_slm.sourcing import orchestrator
from cybersec_slm.sourcing.backends.base import Candidate
from cybersec_slm.sourcing.config import BackendSettings, SourcingConfig
from cybersec_slm.sourcing.search import Result


@pytest.fixture(autouse=True)
def _ubi(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "ubi")
    yield


class _Enrich:
    """Stands in for a real metadata read; fills each row's license from a map."""

    def __init__(self, by_tail=None):
        self._by = by_tail or {}

    def enrich(self, row):
        tail = row["Dataset Link"].rsplit("/", 1)[-1]
        row["License"] = self._by.get(tail, "MIT")
        return row


class _FakeBackend:
    name = "huggingface"          # API backend -> liveness skipped, in enabled order

    def __init__(self, cands):
        self._cands = cands

    def available(self, cfg):
        return True

    def search(self, subdomain, keyword, limit, cfg):
        return list(self._cands)[:limit]


def _cfg(tmp_path, profile="ubi"):
    return SourcingConfig(
        profile=profile, keywords={"AML-KYC": ["aml"]},
        output_csv=str(tmp_path / "Sources.csv"),
        restricted_hosts={"rbi.org.in": "regulator terms", "sebi.gov.in": "regulator terms"},
        backends={"huggingface": BackendSettings(enabled=True, per_keyword_limit=50)},
    )


def _cands(*links):
    return [Candidate(subdomain="AML-KYC", result=Result(title=f"T{i}", link=lk, snippet="s"),
                      backend="huggingface", license="")
            for i, lk in enumerate(links)]


def _run(tmp_path, monkeypatch, cands, enrich_map=None):
    monkeypatch.setattr(orchestrator, "get_backend", lambda name: _FakeBackend(cands))
    monkeypatch.setattr(orchestrator, "Enricher", lambda *a, **k: _Enrich(enrich_map))
    return orchestrator.source(cfg=_cfg(tmp_path), subdomains=["AML-KYC"],
                               max_total=5, enrich=True)


def test_funnel_counts_every_hit_into_exactly_one_bucket(tmp_path, monkeypatch):
    cands = _cands(
        "https://huggingface.co/datasets/a/aml",     # keep -> candidate
        "https://rbi.org.in/master-direction.pdf",   # restricted host
        "https://www.rbi.org.in/circular.pdf",       # restricted host (www)
        "https://sebi.gov.in/legal/x.html",          # restricted host
        "https://youtube.com/watch?v=1",             # junk host
        "https://github.com/topics/aml",             # listing page
        "https://huggingface.co/datasets/a/aml",     # duplicate of #1
    )
    summ = _run(tmp_path, monkeypatch, cands)
    f = summ["funnel"]
    assert f["found"] == 7
    assert f["dropped"]["restricted host"] == 3
    assert f["dropped"]["junk host"] == 1
    assert f["dropped"]["listing page"] == 1
    assert f["duplicates"] == 1
    assert f["candidates"] == 1
    assert f["unprocessed"] == 0
    assert f["found"] == (f["dropped_total"] + f["duplicates"]
                          + f["candidates"] + f["unprocessed"])


def test_funnel_names_the_restricted_hosts_that_cost_the_most(tmp_path, monkeypatch):
    cands = _cands(
        "https://rbi.org.in/a.pdf", "https://rbi.org.in/b.pdf",
        "https://rbi.org.in/c.pdf", "https://sebi.gov.in/d.html",
        "https://huggingface.co/datasets/a/aml",
    )
    summ = _run(tmp_path, monkeypatch, cands)
    hosts = summ["funnel"]["restricted_by_host"]
    assert list(hosts.items()) == [("rbi.org.in", 3), ("sebi.gov.in", 1)]


def test_funnel_records_license_verdicts_of_candidates(tmp_path, monkeypatch):
    cands = _cands("https://huggingface.co/datasets/a/one",
                   "https://huggingface.co/datasets/a/two",
                   "https://huggingface.co/datasets/a/three")
    summ = _run(tmp_path, monkeypatch, cands,
                enrich_map={"one": "MIT", "two": "CC BY-NC 4.0", "three": ""})
    lic = summ["funnel"]["license"]
    assert lic == {"ok": 1, "unknown": 1, "blocked": 1}
    assert sum(lic.values()) == summ["funnel"]["candidates"]


def test_cybersec_profile_bars_nothing_so_the_bucket_stays_empty(tmp_path, monkeypatch):
    """The restricted-host bucket is ubi-specific; under the cybersec profile (which
    declares no restricted hosts) the same hit is a normal candidate, not a drop."""
    from cybersec_slm.sourcing import catalog
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "cybersec")
    sd = catalog.subdomains(catalog.load(profile="cybersec"))[0]
    cand = [Candidate(subdomain=sd, result=Result(title="T", link="https://rbi.org.in/a.pdf",
                                                  snippet="s"), backend="huggingface", license="")]
    monkeypatch.setattr(orchestrator, "get_backend", lambda name: _FakeBackend(cand))
    monkeypatch.setattr(orchestrator, "Enricher", lambda *a, **k: _Enrich())
    cfg = SourcingConfig(
        profile="cybersec", keywords={sd: ["aml"]},
        output_csv=str(tmp_path / "Sources.csv"),
        restricted_hosts={},          # cybersec bars nothing
        backends={"huggingface": BackendSettings(enabled=True, per_keyword_limit=50)})
    summ = orchestrator.source(cfg=cfg, subdomains=[sd], max_total=5, enrich=True)
    assert summ["funnel"]["dropped"]["restricted host"] == 0
    assert summ["funnel"]["candidates"] == 1
