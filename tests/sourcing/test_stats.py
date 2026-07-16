"""The discovery funnel tally.

The funnel's whole value is that it *balances*: every hit lands in exactly one
terminal bucket, so "found" minus the drops minus the duplicates is the candidate
count. A tally that silently loses hits is worse than none, because it reads as
authoritative.
"""

from __future__ import annotations

from cybersec_slm.sourcing.quality import DROP_CATEGORIES, classify
from cybersec_slm.sourcing.search import Result
from cybersec_slm.sourcing.stats import LICENSE_VERDICTS, Funnel


def _res(link: str) -> Result:
    return Result(title="t", link=link, snippet="s")


def test_empty_funnel_reports_stable_zeroed_keys():
    """Every bucket must exist even at zero, so the dashboard table's rows do not
    appear and disappear between runs."""
    d = Funnel().as_dict()
    assert d["found"] == 0 and d["candidates"] == 0
    assert set(d["dropped"]) == set(DROP_CATEGORIES)
    assert set(d["license"]) == set(LICENSE_VERDICTS)
    assert all(v == 0 for v in d["dropped"].values())


def test_unprocessed_absorbs_the_buffer_tail_so_the_funnel_still_closes():
    """`found` counts a hit when it is fetched, not when it is examined, so a run
    that stops on its cap leaves results in the buffer. They must show up as
    `unprocessed`, not vanish — a funnel whose arithmetic does not close is worse
    than no funnel."""
    f = Funnel()
    for _ in range(10):
        f.hit("AML-KYC")
    f.candidate("AML-KYC")           # only one of the ten was ever examined
    d = f.as_dict()
    assert d["unprocessed"] == 9
    assert d["found"] == (d["dropped_total"] + d["duplicates"]
                          + d["candidates"] + d["unprocessed"])


def test_unprocessed_never_goes_negative():
    f = Funnel()
    f.candidate("AML-KYC")           # a candidate with no matching hit
    assert f.as_dict()["unprocessed"] == 0


def test_the_funnel_balances():
    f = Funnel()
    for _ in range(10):
        f.hit("AML-KYC")
    f.drop("AML-KYC", "restricted host", "rbi.org.in")
    f.drop("AML-KYC", "restricted host", "rbi.org.in")
    f.drop("AML-KYC", "junk host", "youtube.com")
    f.duplicate("AML-KYC")
    for _ in range(6):
        f.candidate("AML-KYC")

    d = f.as_dict()
    assert d["found"] == 10
    assert d["dropped_total"] == 3
    assert d["duplicates"] == 1
    assert d["candidates"] == 6
    assert d["unprocessed"] == 0     # everything fetched was examined
    assert d["found"] == (d["dropped_total"] + d["duplicates"]
                          + d["candidates"] + d["unprocessed"])


def test_restricted_hosts_are_tallied_per_host_most_first():
    f = Funnel()
    for _ in range(5):
        f.drop("AML-KYC", "restricted host", "rbi.org.in")
    f.drop("AML-KYC", "restricted host", "sebi.gov.in")
    f.drop("AML-KYC", "junk host", "youtube.com")

    hosts = f.as_dict()["restricted_by_host"]
    assert list(hosts.items()) == [("rbi.org.in", 5), ("sebi.gov.in", 1)]
    assert "youtube.com" not in hosts, "only the restricted bucket tallies per host"


def test_license_verdicts_are_counted():
    f = Funnel()
    for v in ("ok", "ok", "unknown", "blocked"):
        f.verdict(v)
    assert f.as_dict()["license"] == {"ok": 2, "unknown": 1, "blocked": 0 + 1}


def test_per_domain_counts_track_each_domains_aim():
    f = Funnel()
    f.hit("AML-KYC")
    f.candidate("AML-KYC")
    f.hit("Internal Audit")
    f.drop("Internal Audit", "listing page")

    by = f.as_dict()["by_domain"]
    assert by["AML-KYC"] == {"found": 1, "dropped": 0, "candidates": 1}
    assert by["Internal Audit"] == {"found": 1, "dropped": 1, "candidates": 0}


def test_categories_match_what_the_quality_filter_actually_emits(monkeypatch):
    """The tally keys on quality.classify's categories; if those drift apart the
    dashboard silently shows zeros for a bucket that is really filling up."""
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "ubi")
    seen = {
        classify(_res("https://rbi.org.in/x.pdf"))[0],
        classify(_res("https://youtube.com/watch"))[0],
        classify(_res("https://github.com/search?q=a"))[0],
        classify(_res(""))[0],
    }
    assert seen <= set(DROP_CATEGORIES), f"unknown category emitted: {seen}"
    # And each is a bucket the funnel will actually report.
    f = Funnel()
    for cat in seen:
        f.drop("AML-KYC", cat)
    assert sum(f.as_dict()["dropped"].values()) == len(seen)
