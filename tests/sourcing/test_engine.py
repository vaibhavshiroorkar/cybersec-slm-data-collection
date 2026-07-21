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


# ------------------------------------------------- country targeting + filter ---

def test_country_slots_apportions_by_bias_and_is_deterministic():
    slots = orchestrator._country_slots(20, {"India": 0.65, "Global": 0.35})
    assert len(slots) == 20
    assert slots.count("India") == 13 and slots.count("Global") == 7
    # Deterministic, and interleaved rather than blocked, so a run cut short by its
    # cap has still asked both kinds of query.
    assert slots == orchestrator._country_slots(20, {"India": 0.65, "Global": 0.35})
    assert set(slots[:6]) == {"India", "Global"}


def test_country_slots_degrades_to_global_without_bias():
    assert orchestrator._country_slots(3, {}) == ["Global"] * 3
    assert orchestrator._country_slots(0, {"India": 1.0}) == []


def test_targeting_bias_filter_overrides_bias():
    # Aiming a third of the shots at "Global" while hard-filtering for India would
    # spend them fetching rows the filter then discards.
    cfg = _cfg(country_bias={"India": 0.65, "Global": 0.35}, country_filter="India")
    assert cfg.targeting_bias() == {"India": 1.0}
    cfg2 = _cfg(country_bias={"India": 0.65, "Global": 0.35})
    assert cfg2.targeting_bias() == {"India": 0.65, "Global": 0.35}


def test_aim_appends_qualifier_but_not_to_already_local_keywords():
    cfg = _cfg(country_hints={"India": ["rbi"]})
    assert orchestrator._aim("aml dataset", "India", cfg) == "aml dataset India"
    assert orchestrator._aim("aml dataset", "Global", cfg) == "aml dataset"
    # Already names the country, or one of its hint terms -> left alone.
    assert orchestrator._aim("India PMLA corpus", "India", cfg) == "India PMLA corpus"
    assert orchestrator._aim("rbi master direction", "India", cfg) == "rbi master direction"


def test_aim_honours_a_custom_qualifier():
    cfg = _cfg(country_qualifier={"India": "site:.in"})
    assert orchestrator._aim("aml dataset", "India", cfg) == "aml dataset site:.in"


def test_build_shots_aims_queries_at_the_biased_country():
    cfg = _cfg(keywords={"AML-KYC": [f"kw{i}" for i in range(10)]},
               country_bias={"India": 1.0})
    shots = orchestrator._build_shots(cfg, ["AML-KYC"])
    queries = {kw for _b, kw in shots["AML-KYC"]}
    assert queries == {f"kw{i} India" for i in range(10)}


def test_country_ok_gate():
    cfg = _cfg(country_filter="India")
    assert gates.country_ok({"Country": "India"}, cfg) is True
    assert gates.country_ok({"Country": "Global"}, cfg) is False
    # Unclassified is not the same as wrong — a blank is kept.
    assert gates.country_ok({"Country": ""}, cfg) is True
    # No filter configured -> everything passes.
    assert gates.country_ok({"Country": "Global"}, _cfg()) is True


def test_country_for_uses_configured_hints():
    from cybersec_slm.sourcing.row import country_for
    assert country_for("https://rbi.org.in/x") == "India"          # ccTLD
    assert country_for("https://example.com/x", "world bank data") == "Global"
    # A profile hint promotes an otherwise-global-looking host.
    assert country_for("https://example.com/x", "Reserve Bank circular",
                       {"India": ["reserve bank"]}) == "India"


def test_orchestrator_country_filter_drops_non_indian_rows(tmp_path, monkeypatch,
                                                           _iso_logs):
    fake = _FakeBackend({
        "aml India": [
            # .in ccTLD -> India, kept.
            _cand("https://data.gov.in/dataset/aml", "AML-KYC"),
            # Plainly global -> dropped by the filter.
            _cand("https://huggingface.co/datasets/x/global-aml", "AML-KYC"),
        ],
        "audit India": [],
    })
    monkeypatch.setattr(orchestrator, "get_backend", lambda name: fake)
    cfg = _cfg(output_csv=str(tmp_path / "Sources.csv"), country_filter="India")
    summ = orchestrator.source(cfg=cfg, enrich=False)

    assert summ["new"] == 1
    assert summ["funnel"]["dropped"]["wrong country"] == 1
    import pandas as pd
    df = pd.read_csv(str(tmp_path / "Sources.csv"), dtype=str, keep_default_na=False)
    assert list(df["Country"]) == ["India"]


def test_orchestrator_flags_restricted_hosts_instead_of_dropping(tmp_path, monkeypatch,
                                                                 _iso_logs):
    fake = _FakeBackend({"aml": [_cand("https://rbi.org.in/rss.xml", "AML-KYC",
                                       license="MIT")], "audit": []})
    monkeypatch.setattr(orchestrator, "get_backend", lambda name: fake)
    cfg = _cfg(output_csv=str(tmp_path / "Sources.csv"), restricted_policy="flag")
    summ = orchestrator.source(cfg=cfg, enrich=False)

    assert summ["new"] == 1, "flag policy admits the row rather than dropping it"
    assert summ["funnel"]["dropped"]["restricted host"] == 0
    assert summ["funnel"]["restricted_flagged_by_host"] == {"rbi.org.in": 1}

    import pandas as pd
    df = pd.read_csv(str(tmp_path / "Sources.csv"), dtype=str, keep_default_na=False)
    # The backend's licence is blanked: a restricted host's terms are not settled by
    # whatever metadata came back, so the row goes to ingestion as Unknown.
    assert df.loc[0, "License"] == ""
    assert "RESTRICTED HOST" in df.loc[0, "Note"]
    assert "all-rights-reserved" in df.loc[0, "Note"] or "commercial reuse" in df.loc[0, "Note"]


def test_restricted_drop_is_still_the_default(tmp_path, monkeypatch, _iso_logs):
    fake = _FakeBackend({"aml": [_cand("https://rbi.org.in/x", "AML-KYC")], "audit": []})
    monkeypatch.setattr(orchestrator, "get_backend", lambda name: fake)
    cfg = _cfg(output_csv=str(tmp_path / "Sources.csv"))   # restricted_policy: "drop"
    summ = orchestrator.source(cfg=cfg, enrich=False)
    assert summ["new"] == 0
    assert summ["funnel"]["dropped"]["restricted host"] == 1


def test_config_rejects_an_unknown_restricted_policy(tmp_path, monkeypatch):
    from cybersec_slm.sourcing import config as c
    p = tmp_path / "sourcing.yaml"
    p.write_text("license:\n  restricted_policy: maybe\n", encoding="utf-8")
    monkeypatch.setattr(c, "_resolve_paths", lambda prof: ("ubi", str(p)))
    with pytest.raises(ValueError, match="restricted_policy"):
        c.load("ubi")
