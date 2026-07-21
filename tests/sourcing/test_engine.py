"""Tests for the rebuilt sourcing engine: gates, config, backends, orchestrator.

Offline — no network. A fake backend (registered under the ``huggingface`` name so
it flows through the normal enabled-backend path and skips the liveness check)
feeds Candidates into the real orchestrator, gate, dedup, and catalog writer.
"""

from __future__ import annotations

import pytest

from cybersec_slm.sourcing import config as cfgmod
from cybersec_slm.sourcing import gates, orchestrator
from cybersec_slm.sourcing.backends.base import Candidate
from cybersec_slm.sourcing.config import BackendSettings, SourcingConfig
from cybersec_slm.sourcing.search import Result


# --------------------------------------------------------------------- gates ---

def _res(link, title="t", snippet="s"):
    return Result(title=title, link=link, snippet=snippet)


def _cfg(**kw):
    base = dict(
        profile="ubi",
        keywords={"AML-KYC": ["aml"], "Internal Audit": ["audit"]},
        output_csv="",
        restricted_hosts={"rbi.org.in": "regulator terms forbid commercial reuse"},
        backends={"huggingface": BackendSettings(enabled=True, per_keyword_limit=50)},
    )
    base.update(kw)
    return SourcingConfig(**base)


def test_gate_restricted_host_beats_everything():
    # rbi.org.in is a trusted-looking gov host, but it is restricted — it must drop,
    # which is exactly the contradiction the old hybrid scorer got wrong.
    cfg = _cfg()
    r = gates.classify_host(_res("https://rbi.org.in/notification/123"), cfg)
    assert r is not None and r.stage == gates.RESTRICTED


def test_gate_drops_junk_and_listing_pages():
    cfg = _cfg()
    assert gates.classify_host(_res("https://youtube.com/watch?v=x"), cfg).stage == gates.JUNK
    assert gates.classify_host(_res("https://github.com/search?q=aml"), cfg).stage == gates.LISTING
    assert gates.classify_host(_res("https://huggingface.co/datasets/a/b"), cfg) is None


def test_gate_extra_restricted_from_config():
    cfg = _cfg(restricted_hosts={"example.com": "blocked by sourcing.yaml"})
    r = gates.classify_host(_res("https://sub.example.com/x"), cfg)
    assert r is not None and r.stage == gates.RESTRICTED


def test_resolve_license_blocks_copyleft_and_keeps_permissive():
    cfg = _cfg()
    assert gates.resolve_license({"License": "GPL-3.0"}, cfg, None) == "blocked"
    assert gates.resolve_license({"License": "MIT"}, cfg, None) == "ok"
    assert gates.resolve_license({"License": ""}, cfg, None) == "unknown"


def test_resolve_license_downgrades_first_party_unless_opted_in():
    cfg = _cfg()  # allow_owned_first_party defaults False
    row = {"License": "First-party (owner-authorized)"}
    assert gates.resolve_license(row, cfg, None) == "unknown"
    assert row["License"] == ""                     # the fabricated-ish stamp is cleared

    cfg2 = _cfg(allow_owned_first_party=True)
    row2 = {"License": "First-party (owner-authorized)"}
    assert gates.resolve_license(row2, cfg2, None) == "ok"


def test_resolve_license_enriches_unknown_from_real_metadata():
    cfg = _cfg(enrich_unknown=True)

    class _Enr:
        def enrich(self, row):
            row["License"] = "Apache-2.0"           # stands in for a real metadata read
            return row

    row = {"License": "", "Dataset Link": "https://huggingface.co/datasets/a/b"}
    assert gates.resolve_license(row, cfg, _Enr()) == "ok"
    assert row["License"] == "Apache-2.0"


def test_is_live_uses_head_then_get(monkeypatch):
    class _Resp:
        def __init__(self, code): self.status_code = code
    assert gates.is_live("http://x", _head=lambda u: _Resp(200)) is True
    assert gates.is_live("http://x", _head=lambda u: _Resp(404)) is False
    # 405 on HEAD falls back to GET
    assert gates.is_live("http://x", _head=lambda u: _Resp(405),
                         _get=lambda u: _Resp(200)) is True


# ---------------------------------------------------------------- backends -----

def test_hf_license_mapping_blanks_unknown():
    from cybersec_slm.sourcing.backends.huggingface import _license
    assert _license(["license:mit"]) == "MIT"
    assert _license(["license:unknown"]) == ""       # never a fabricated value
    assert _license(["task:x"]) == ""                # no license tag -> blank


def test_zenodo_license_mapping():
    from cybersec_slm.sourcing.backends.zenodo import _license
    assert _license({"license": {"id": "cc-by-4.0"}}) == "CC BY 4.0"
    assert _license({}) == ""


# ------------------------------------------------------------- orchestrator ----

class _FakeBackend:
    """Yields preset Candidates; registered under the 'huggingface' name so it is an
    API backend (liveness skipped) and appears in the enabled-backend order."""

    name = "huggingface"

    def __init__(self, by_keyword):
        self._by = by_keyword

    def available(self, cfg):
        return True

    def search(self, subdomain, keyword, limit, cfg):
        return list(self._by.get(keyword, []))[:limit]


def _cand(link, subdomain, license="MIT"):
    return Candidate(subdomain=subdomain, result=_res(link), backend="huggingface",
                     license=license)


@pytest.fixture
def _iso_logs(tmp_path, monkeypatch):
    monkeypatch.setattr(orchestrator, "LOGS", str(tmp_path / "logs"), raising=False)
    yield


def _run(tmp_path, monkeypatch, fake, **kw):
    monkeypatch.setattr(orchestrator, "get_backend", lambda name: fake)
    cfg = _cfg(output_csv=str(tmp_path / "Sources.csv"))
    return orchestrator.source(cfg=cfg, enrich=False, **kw)


def test_orchestrator_appends_kept_rows_with_real_license(tmp_path, monkeypatch, _iso_logs):
    fake = _FakeBackend({
        "aml": [_cand("https://huggingface.co/datasets/x/aml1", "AML-KYC")],
        "audit": [_cand("https://huggingface.co/datasets/x/aud1", "Internal Audit")],
    })
    summ = _run(tmp_path, monkeypatch, fake)
    assert summ["new"] == 2 and summ["appended"] == 2
    import pandas as pd
    df = pd.read_csv(summ["csv"] if False else str(tmp_path / "Sources.csv"),
                     dtype=str, keep_default_na=False)
    assert set(df["License"]) == {"MIT"}            # backend metadata license, not fabricated


def test_orchestrator_drops_restricted_and_blocked(tmp_path, monkeypatch, _iso_logs):
    fake = _FakeBackend({
        "aml": [
            _cand("https://rbi.org.in/x", "AML-KYC"),               # restricted host
            _cand("https://huggingface.co/datasets/x/g", "AML-KYC", license="GPL-3.0"),  # blocked
            _cand("https://huggingface.co/datasets/x/ok", "AML-KYC", license="MIT"),     # kept
        ],
        "audit": [],
    })
    summ = _run(tmp_path, monkeypatch, fake)
    assert summ["new"] == 1
    f = summ["funnel"]
    assert f["dropped"]["restricted host"] == 1
    assert f["license"]["blocked"] == 1
    assert f["license"]["ok"] == 1


def test_orchestrator_dedups_within_run_and_against_catalog(tmp_path, monkeypatch, _iso_logs):
    link = "https://huggingface.co/datasets/x/dup"
    fake = _FakeBackend({"aml": [_cand(link, "AML-KYC"), _cand(link, "AML-KYC")],
                         "audit": []})
    summ = _run(tmp_path, monkeypatch, fake)
    assert summ["new"] == 1                         # the duplicate was dropped
    assert summ["funnel"]["duplicates"] == 1


def test_orchestrator_respects_global_cap(tmp_path, monkeypatch, _iso_logs):
    fake = _FakeBackend({
        "aml": [_cand(f"https://huggingface.co/datasets/x/a{i}", "AML-KYC") for i in range(10)],
        "audit": [_cand(f"https://huggingface.co/datasets/x/b{i}", "Internal Audit") for i in range(10)],
    })
    summ = _run(tmp_path, monkeypatch, fake, max_total=5)
    assert summ["new"] == 5


def test_orchestrator_never_fabricates_a_license(tmp_path, monkeypatch, _iso_logs):
    # A backend that returns NO license must never yield a row with an invented one:
    # with enrich off, the row is kept as Unknown (blank), not stamped first-party.
    fake = _FakeBackend({"aml": [_cand("https://huggingface.co/datasets/x/nolic",
                                       "AML-KYC", license="")], "audit": []})
    summ = _run(tmp_path, monkeypatch, fake)
    import pandas as pd
    df = pd.read_csv(str(tmp_path / "Sources.csv"), dtype=str, keep_default_na=False)
    assert list(df["License"]) == [""]              # blank, never a fabricated stamp
    assert summ["funnel"]["license"]["unknown"] == 1


def test_keyword_relevance_floor_drops_off_topic_but_keeps_on_topic():
    """The topicality floor must keep a real AML dataset and drop the beetle."""
    cfg = _cfg()
    cfg.quality.min_keyword_hits = 1
    terms = ("aml", "kyc", "money laundering", "financial crime")

    ok, hits = gates.keyword_relevance(
        "IBM AMLSim Example Dataset — synthetic money laundering transactions",
        terms, cfg)
    assert ok and hits >= 1

    ok, hits = gates.keyword_relevance(
        "Elaeonoma ultima Tomura, Yagi & Hirowatari, 2026, sp. nov.", terms, cfg)
    assert not ok and hits == 0


def test_keyword_relevance_is_off_by_default():
    cfg = _cfg()                       # min_keyword_hits defaults to 0
    ok, _ = gates.keyword_relevance("totally unrelated text", ("aml",), cfg)
    assert ok


def test_orchestrator_drops_low_relevance_candidates(tmp_path, monkeypatch, _iso_logs):
    fake = _FakeBackend({
        "aml": [_cand("https://huggingface.co/datasets/x/beetle", "AML-KYC"),
                _cand("https://huggingface.co/datasets/x/aml", "AML-KYC")],
        "audit": [],
    })
    monkeypatch.setattr(orchestrator, "get_backend", lambda name: fake)
    cfg = _cfg(output_csv=str(tmp_path / "Sources.csv"))
    cfg.quality.min_keyword_hits = 1
    # The fake registers as "huggingface"; scope the floor to it for this test.
    cfg.quality.relevance_backends = ["huggingface"]
    # _cand builds Result(title="t", snippet="s"); give the second one real topic words.
    fake._by["aml"][1].result = _res("https://huggingface.co/datasets/x/aml",
                                     title="AML transaction monitoring",
                                     snippet="money laundering detection dataset")
    summ = orchestrator.source(cfg=cfg, enrich=False)
    assert summ["new"] == 1                       # only the on-topic one survived
    assert summ["funnel"]["dropped_total"] >= 1


def test_relevance_floor_is_scoped_to_the_broad_backends(tmp_path, monkeypatch,
                                                         _iso_logs):
    """A terse-but-on-topic dataset-API row must NOT be dropped by the floor: the
    dataset APIs are already query-bound, and applying the floor to them threw away
    5 of 12 real Kaggle rows (the Elliptic AML set among them)."""
    fake = _FakeBackend({"aml": [_cand("https://huggingface.co/datasets/x/elliptic",
                                       "AML-KYC")], "audit": []})
    monkeypatch.setattr(orchestrator, "get_backend", lambda name: fake)
    cfg = _cfg(output_csv=str(tmp_path / "Sources.csv"))
    cfg.quality.min_keyword_hits = 1
    cfg.quality.relevance_backends = ["zenodo", "arxiv", "searxng"]  # not huggingface
    summ = orchestrator.source(cfg=cfg, enrich=False)
    assert summ["new"] == 1                       # kept despite zero vocab hits


def test_shots_interleave_backends_instead_of_draining_one(tmp_path):
    """Every backend must get a turn on keyword 1 before any sees keyword 2.

    Regression: shots used to be backend-major, so an unreachable backend
    (data.gov.in times out on every request) burned one timeout per keyword —
    119 of them — before any other backend ran, which looks like a hung run.
    """
    cfg = _cfg(keywords={"AML-KYC": ["a", "b"]},
               backends={"huggingface": BackendSettings(enabled=True),
                         "github": BackendSettings(enabled=True)})
    shots = list(orchestrator._build_shots(cfg, ["AML-KYC"])["AML-KYC"])
    assert shots == [("huggingface", "a"), ("github", "a"),
                     ("huggingface", "b"), ("github", "b")]


def test_circuit_breaker_retires_a_backend_that_keeps_returning_nothing(
        tmp_path, monkeypatch, _iso_logs):
    """A backend that comes back empty N times in a row is dropped for the run,
    so an unreachable host cannot cost one timeout per keyword forever."""
    calls = {"n": 0}

    class _DeadBackend:
        name = "huggingface"

        def available(self, cfg):
            return True

        def search(self, subdomain, keyword, limit, cfg):
            calls["n"] += 1
            return []                      # always empty, like a timing-out host

    monkeypatch.setattr(orchestrator, "get_backend", lambda name: _DeadBackend())
    cfg = _cfg(output_csv=str(tmp_path / "Sources.csv"),
               keywords={"AML-KYC": [f"kw{i}" for i in range(20)]})
    cfg.max_consecutive_empty = 3

    summ = orchestrator.source(cfg=cfg, enrich=False)

    assert calls["n"] == 3, "backend should be retired after 3 empty shots"
    assert summ["new"] == 0


def test_config_load_falls_back_to_taxonomy(tmp_path, monkeypatch):
    cfg = cfgmod.default_config("ubi")
    assert cfg.enabled_backends()[0] != "searxng"   # searxng is last-resort
    assert cfg.enabled_backends()[-1] == "searxng"
    assert "rbi.org.in" in cfg.restricted_hosts
