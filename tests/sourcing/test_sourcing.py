"""Offline tests for the sourcing stage — pure logic, no network/credentials."""

from cybersec_slm.sourcing import keywords as kw
from cybersec_slm.sourcing.classify import infer_category_and_format, refine_domain
from cybersec_slm.sourcing.row import (
    SHEET_COLUMNS,
    build_manual_row,
    build_row,
    row_to_list,
)
from cybersec_slm.sourcing.search import Result, _parse_items
from cybersec_slm.sourcing.sheet import (
    append_rows,
    delete_rows,
    existing_links,
    normalize_url,
    rename_subdomain,
)

# ----------------------------------------------------------------- keywords ---


def test_every_domain_has_keywords_and_vocab():
    assert kw.DOMAIN_KEYWORDS, "no domains configured"
    for domain, words in kw.DOMAIN_KEYWORDS.items():
        assert words, f"{domain} has no keywords"
        assert domain in kw.DOMAIN_VOCAB, f"{domain} missing vocab"
        assert kw.DOMAIN_VOCAB[domain], f"{domain} vocab empty"


def test_every_domain_has_ample_dataset_keywords():
    # The GitHub engine is single-page, so breadth (many distinct keywords) is the
    # only lever for wider commercial-valid coverage per sub-domain.
    for domain, words in kw.DOMAIN_KEYWORDS.items():
        assert len(words) >= 12, f"{domain} has too few keywords ({len(words)})"
        assert len(words) == len(set(words)), f"{domain} has duplicate keywords"


def test_default_engines_are_github_first_and_reliable():
    ds = kw.default_engines(is_datasets=True)
    assert ds.split(",")[0] == "github"            # highest commercial-valid yield
    for eng in ("openairedatasets", "arxiv", "semantic scholar"):
        assert eng in ds
    # None of the rate-limited general web engines are in the default set.
    for dead in ("google", "duckduckgo", "brave", "startpage", "bing"):
        assert dead not in ds
    txt = kw.default_engines(is_datasets=False)
    assert "github" in txt


# ----------------------------------------------------------------- classify ---


def test_infer_category_and_format():
    assert infer_category_and_format(
        "https://huggingface.co/datasets/foo/bar") == ("Dataset", "")
    assert infer_category_and_format(
        "https://github.com/foo/bar") == ("Repository", "")
    assert infer_category_and_format(
        "https://example.com/report.pdf") == ("Document", "PDF")
    assert infer_category_and_format(
        "https://example.com/data.csv") == ("Dataset", "CSV")
    assert infer_category_and_format("https://someblog.io/post") == ("Website", "HTML")


def test_refine_domain_keeps_default_on_tie():
    # No distinctive terms -> stays with the keyword's domain.
    assert refine_domain("Cloud Security", "Some title", "generic text") == "Cloud Security"


def test_refine_domain_reassigns_on_stronger_signal():
    # Searched under Network Security but the text screams cryptography.
    domain = refine_domain(
        "Network Security",
        "Post-quantum key exchange",
        "lattice-based post-quantum cryptography ml-kem certificate over tls")
    assert domain == "Cryptography"


# ---------------------------------------------------------------- row build ---


def test_build_row_fills_known_fields_only():
    res = Result(title="CyberCorp Dataset | HF",
                 link="https://huggingface.co/datasets/CyberCorp/threats",
                 snippet="A corpus of phishing IOC indicators of compromise.",
                 display_link="huggingface.co")
    row = build_row(res, "Threat Intelligence", today="01/01/2026")
    assert set(row) == set(SHEET_COLUMNS)
    assert row["Name"] == "CyberCorp"            # HF org, not the title
    assert row["Sub-Domain"] == "Threat Intelligence"
    assert row["Dataset Link"] == res.link
    assert row["Category"] == "Dataset"
    assert row["Date Added"] == "01/01/2026"
    # Ingestion/cleaning-dependent fields stay blank.
    for blank in ("File Count", "Total Lines", "Verified?", "Uploaded?", "License",
                  "Cleaned?", "Cleaned Size (MB)", "Cleaned Lines"):
        assert row[blank] == ""


def test_row_to_list_matches_column_order():
    res = Result(title="x", link="https://example.com/a", snippet="s")
    row = build_row(res, "Network Security", today="02/02/2026")
    values = row_to_list(row)
    assert len(values) == len(SHEET_COLUMNS)
    assert values[SHEET_COLUMNS.index("Dataset Link")] == "https://example.com/a"


# ------------------------------------------------------------------- dedup ----


def test_normalize_url_canonicalizes():
    a = normalize_url("https://www.Example.com/Path/")
    b = normalize_url("http://example.com/Path")
    assert a == b == "example.com/path"


def test_append_rows_and_existing_links_round_trip(tmp_path):
    import csv as _csv

    csv_path = str(tmp_path / "Sources.csv")
    res = Result(title="Foo", link="https://huggingface.co/datasets/foo/bar",
                 snippet="desc")
    rows = [build_row(res, "Cloud Security", today="01/01/2026")]

    # Append to a fresh catalog -> creates it with the 19-col header.
    assert append_rows(csv_path, rows) == 1
    with open(csv_path, encoding="utf-8") as f:
        header, *data = list(_csv.reader(f))
    assert header == list(SHEET_COLUMNS)              # full canonical header
    assert len(data) == 1
    # Unfilled cells are blank strings, never the literal "nan".
    assert "nan" not in [c.strip().lower() for c in data[0]]

    # existing_links recognizes the appended link (normalized).
    links = existing_links(csv_path)
    assert normalize_url("https://huggingface.co/datasets/foo/bar") in links

    # A second append with the same link still writes (dedup is the caller's job),
    # and existing_links on a missing file is just empty.
    assert existing_links(str(tmp_path / "nope.csv")) == set()


def test_append_rows_unions_new_columns_into_legacy_file(tmp_path):
    import pandas as pd

    csv_path = str(tmp_path / "Sources.csv")
    # A catalog written before enrichment existed: no Author/Popularity/Tags.
    legacy = ["Name", "Sub-Domain", "Dataset Link", "License"]
    pd.DataFrame([{"Name": "Old", "Sub-Domain": "D",
                   "Dataset Link": "https://a", "License": "MIT"}],
                 columns=legacy).to_csv(csv_path, index=False, encoding="utf-8")

    # Append a row carrying a new column (Author) -> it is unioned into the header.
    append_rows(csv_path, [{"Name": "New", "Sub-Domain": "D",
                            "Dataset Link": "https://b", "Author": "octo"}])
    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False, encoding="utf-8")
    assert "Author" in df.columns
    assert list(df.columns[:4]) == legacy            # legacy order preserved
    assert df.iloc[0]["Author"] == ""                # legacy row left blank
    assert df.iloc[1]["Author"] == "octo"            # new row filled


def test_discover_enriches_rows_when_enabled(tmp_path, monkeypatch):
    import pandas as pd

    from cybersec_slm.sourcing import run
    from cybersec_slm.sourcing.search import Result

    hit = Result(title="T", link="https://huggingface.co/datasets/x/y", snippet="s")
    monkeypatch.setattr(run, "searxng_search", lambda *a, **k: [hit])

    enriched: list[str] = []

    class _SpyEnricher:
        def __init__(self, **kw):
            pass

        def enrich(self, row):
            enriched.append(row["Dataset Link"])
            row["License"] = "MIT"
            return row

    monkeypatch.setattr(run, "Enricher", _SpyEnricher)

    csv_path = str(tmp_path / "Sources.csv")
    dom = run.catalog.subdomains(run.catalog.load())[0]
    summ = run.discover(csv_path, domains=[dom], per_keyword=1, max_total=1,
                        enrich=True)

    assert summ["new"] == 1
    assert enriched == ["https://huggingface.co/datasets/x/y"]
    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False, encoding="utf-8")
    assert df.iloc[0]["License"] == "MIT"            # enrichment landed in the row


def test_discover_skips_enrichment_when_disabled(tmp_path, monkeypatch):
    from cybersec_slm.sourcing import run
    from cybersec_slm.sourcing.search import Result

    monkeypatch.setattr(run, "searxng_search", lambda *a, **k: [
        Result(title="T", link="https://huggingface.co/datasets/x/y", snippet="s")])

    built: list[int] = []

    class _SpyEnricher:
        def __init__(self, **kw):
            built.append(1)

        def enrich(self, row):
            return row

    monkeypatch.setattr(run, "Enricher", _SpyEnricher)

    dom = run.catalog.subdomains(run.catalog.load())[0]
    run.discover(str(tmp_path / "S.csv"), domains=[dom], per_keyword=1,
                 max_total=1, enrich=False)
    assert built == []                               # Enricher never constructed


def test_discover_paginates_until_target_reached(tmp_path, monkeypatch):
    # Each result page yields one new link (the same one for every keyword on that
    # page, so dedup leaves exactly one per page). Reaching a target of 3 therefore
    # requires walking to page 3 - proving the run keeps going past the first page.
    from cybersec_slm.sourcing import run
    from cybersec_slm.sourcing.search import Result

    seen_pages: list[int] = []

    def fake_search(query, *, url=None, num=10, language="en", client=None,
                    pageno=1, **k):
        seen_pages.append(pageno)
        if pageno <= 5:
            return [Result(title="T", link=f"https://example.com/page{pageno}",
                           snippet="s")]
        return []

    monkeypatch.setattr(run, "searxng_search", fake_search)

    dom = run.catalog.subdomains(run.catalog.load())[0]
    summ = run.discover(str(tmp_path / "S.csv"), domains=[dom], per_keyword=1,
                        max_total=3, enrich=False)

    assert summ["new"] == 3
    assert summ["target"] == 3
    assert summ["target_reached"] is True
    assert max(seen_pages) >= 3               # actually paged past page 1


def test_discover_stops_when_search_space_exhausted(tmp_path, monkeypatch):
    # Only two pages ever return results; the target (100) can never be met, so the
    # run must stop at what exists instead of looping forever.
    from cybersec_slm.sourcing import run
    from cybersec_slm.sourcing.search import Result

    def fake_search(query, *, url=None, num=10, language="en", client=None,
                    pageno=1, **k):
        if pageno <= 2:
            return [Result(title="T", link=f"https://example.com/page{pageno}",
                           snippet="s")]
        return []

    monkeypatch.setattr(run, "searxng_search", fake_search)

    dom = run.catalog.subdomains(run.catalog.load())[0]
    summ = run.discover(str(tmp_path / "S.csv"), domains=[dom], per_keyword=1,
                        max_total=100, enrich=False)

    assert summ["new"] == 2                    # only what the space held
    assert summ["target_reached"] is False


def test_discover_single_pass_when_no_target(tmp_path, monkeypatch):
    # Without max_total the run makes exactly one pass (page 1 only), unchanged.
    from cybersec_slm.sourcing import run
    from cybersec_slm.sourcing.search import Result

    seen_pages: list[int] = []

    def fake_search(query, *, url=None, num=10, language="en", client=None,
                    pageno=1, **k):
        seen_pages.append(pageno)
        return [Result(title="T", link=f"https://example.com/{query}", snippet="s")]

    monkeypatch.setattr(run, "searxng_search", fake_search)

    dom = run.catalog.subdomains(run.catalog.load())[0]
    summ = run.discover(str(tmp_path / "S.csv"), domains=[dom], enrich=False)

    assert set(seen_pages) == {1}              # never paged beyond the first
    assert summ["target"] is None
    assert summ["target_reached"] is True


def test_valid_counts_by_subdomain_counts_only_commercial_ok(tmp_path):
    import pandas as pd

    from cybersec_slm.sourcing.sheet import valid_counts_by_subdomain

    csv_path = str(tmp_path / "Sources.csv")
    pd.DataFrame([
        {"Sub-Domain": "Cryptography", "Dataset Link": "https://a", "License": "MIT"},
        {"Sub-Domain": "Cryptography", "Dataset Link": "https://b", "License": "Apache-2.0"},
        {"Sub-Domain": "Cryptography", "Dataset Link": "https://c", "License": "CC BY-NC 4.0"},
        {"Sub-Domain": "Cryptography", "Dataset Link": "https://d", "License": ""},
        {"Sub-Domain": "Network Security", "Dataset Link": "https://e", "License": "BSD-3-Clause"},
        {"Sub-Domain": "Network Security", "Dataset Link": "https://f", "License": "GPL-3.0"},
    ]).to_csv(csv_path, index=False, encoding="utf-8")

    counts = valid_counts_by_subdomain(csv_path)
    assert counts["Cryptography"] == 2         # MIT + Apache; NC and blank excluded
    assert counts["Network Security"] == 1     # BSD ok; GPL blocked


def test_valid_counts_by_subdomain_missing_file_is_empty(tmp_path):
    from cybersec_slm.sourcing.sheet import valid_counts_by_subdomain

    assert valid_counts_by_subdomain(str(tmp_path / "nope.csv")) == {}


def test_delete_rows_by_subdomain_and_link(tmp_path):
    csv_path = str(tmp_path / "Sources.csv")
    rows = [
        build_row(Result(title="A", link="https://huggingface.co/datasets/a/x",
                         snippet="s"), "Cloud Security", today="01/01/2026"),
        build_row(Result(title="B", link="https://github.com/b/y", snippet="s"),
                  "Network Security", today="01/01/2026"),
        build_row(Result(title="C", link="https://example.com/c", snippet="s"),
                  "Network Security", today="01/01/2026"),
    ]
    append_rows(csv_path, rows)

    # delete every Network Security row (group delete)
    assert delete_rows(csv_path, subdomains=["Network Security"]) == 2
    links = existing_links(csv_path)
    assert normalize_url("https://huggingface.co/datasets/a/x") in links
    assert len(links) == 1

    # delete a single row by link (normalized match: www/scheme differences ok)
    assert delete_rows(csv_path, links=["http://www.huggingface.co/datasets/a/x/"]) == 1
    assert existing_links(csv_path) == set()

    # no-op cases
    assert delete_rows(csv_path, subdomains=["Nope"]) == 0
    assert delete_rows(str(tmp_path / "missing.csv"), links=["x"]) == 0


def test_delete_rows_by_position(tmp_path):
    csv_path = str(tmp_path / "Sources.csv")
    rows = [
        build_row(Result(title=name, link=f"https://example.com/{name}",
                         snippet="s"), "Network Security", today="01/01/2026")
        for name in ("A", "B", "C", "D")
    ]
    append_rows(csv_path, rows)

    # 1-based inclusive range: delete rows 2..3 (B, C), keep A and D.
    assert delete_rows(csv_path, positions=[2, 3]) == 2
    links = existing_links(csv_path)
    assert normalize_url("https://example.com/A") in links
    assert normalize_url("https://example.com/D") in links
    assert len(links) == 2

    # out-of-range positions are ignored, not errors
    assert delete_rows(csv_path, positions=[99]) == 0


# ------------------------------------------------------ discover: new behavior --


def test_discover_spreads_evenly_across_domains(tmp_path, monkeypatch):
    # Every keyword yields a fresh unique link, so the only thing bounding the run
    # is the total cap. With an odd cap over two domains, the round-robin schedule
    # must split them as evenly as possible (differ by at most one).
    from cybersec_slm.sourcing import run
    from cybersec_slm.sourcing.search import Result

    counter = {"n": 0}

    def fake_search(query, *, pageno=1, **k):
        counter["n"] += 1
        return [Result(title="T", link=f"https://example.com/r{counter['n']}",
                       snippet="s")]

    monkeypatch.setattr(run, "searxng_search", fake_search)

    doms = run.catalog.subdomains(run.catalog.load())[:2]
    summ = run.discover(str(tmp_path / "S.csv"), domains=doms, per_keyword=1,
                        max_total=5, enrich=False)

    assert summ["new"] == 5
    counts = sorted(summ["by_domain"][d] for d in doms)
    assert counts[1] - counts[0] <= 1          # even split (3 and 2)


def test_discover_survives_a_failing_query(tmp_path, monkeypatch):
    # One keyword's search raises; the run logs and skips it, and still gathers
    # rows from the queries that succeed (no whole-run abort).
    from cybersec_slm.sourcing import run
    from cybersec_slm.sourcing.search import Result, SearchError

    calls = {"n": 0}

    def flaky_search(query, *, pageno=1, **k):
        calls["n"] += 1
        if calls["n"] == 2:                    # the 2nd query blows up
            raise SearchError("boom")
        return [Result(title="T", link=f"https://example.com/ok{calls['n']}",
                       snippet="s")]

    monkeypatch.setattr(run, "searxng_search", flaky_search)

    dom = run.catalog.subdomains(run.catalog.load())[0]
    summ = run.discover(str(tmp_path / "S.csv"), domains=[dom], per_keyword=1,
                        max_total=3, enrich=False)

    assert summ["new"] == 3                     # gathered despite the failure


def test_discover_first_query_failure_is_fatal(tmp_path, monkeypatch):
    # If the very first query fails, the instance is unreachable/misconfigured, so
    # discovery fails fast with a clear error rather than churning through every
    # keyword.
    import pytest

    from cybersec_slm.sourcing import run
    from cybersec_slm.sourcing.search import SearchError

    def dead_search(query, *, pageno=1, **k):
        raise SearchError("connection refused")

    monkeypatch.setattr(run, "searxng_search", dead_search)

    dom = run.catalog.subdomains(run.catalog.load())[0]
    with pytest.raises(SearchError):
        run.discover(str(tmp_path / "S.csv"), domains=[dom], per_keyword=1,
                     max_total=3, enrich=False)


def test_discover_stops_on_time_budget(tmp_path, monkeypatch):
    # A tiny time budget (via an injected clock that trips after a few ticks) stops
    # the run early even though the search space is effectively infinite.
    from cybersec_slm.sourcing import run
    from cybersec_slm.sourcing.search import Result

    counter = {"n": 0}

    def fake_search(query, *, pageno=1, **k):
        counter["n"] += 1
        return [Result(title="T", link=f"https://example.com/t{counter['n']}",
                       snippet="s")]

    monkeypatch.setattr(run, "searxng_search", fake_search)

    ticks = {"n": 0}

    def clock():                                # 0 for the first few calls, then jump
        ticks["n"] += 1
        return 0.0 if ticks["n"] <= 6 else 10_000.0

    dom = run.catalog.subdomains(run.catalog.load())[0]
    summ = run.discover(str(tmp_path / "S.csv"), domains=[dom], per_keyword=1,
                        max_minutes=1, enrich=False, clock=clock)

    assert summ["max_minutes"] == 1
    assert 0 < summ["new"] < 8                  # stopped well before exhausting


def test_discover_reports_license_fill(tmp_path, monkeypatch):
    from cybersec_slm.sourcing import run
    from cybersec_slm.sourcing.search import Result

    monkeypatch.setattr(run, "searxng_search", lambda *a, **k: [
        Result(title="T", link="https://huggingface.co/datasets/x/y", snippet="s")])

    class _SpyEnricher:
        def __init__(self, **kw):
            pass

        def enrich(self, row):
            row["License"] = "MIT"
            return row

    monkeypatch.setattr(run, "Enricher", _SpyEnricher)

    dom = run.catalog.subdomains(run.catalog.load())[0]
    summ = run.discover(str(tmp_path / "S.csv"), domains=[dom], per_keyword=1,
                        max_total=1, enrich=True)

    assert summ["new"] == 1
    assert summ["license_filled"] == 1
    assert summ["license_rate"] == 1.0


def test_discover_quality_filter_drops_junk(tmp_path, monkeypatch):
    # A junk (social) result and a good one arrive together; only the good one is
    # kept when the quality filter is on.
    from cybersec_slm.sourcing import run
    from cybersec_slm.sourcing.search import Result

    monkeypatch.setattr(run, "searxng_search", lambda *a, **k: [
        Result(title="junk", link="https://www.youtube.com/watch?v=x", snippet="s"),
        Result(title="good", link="https://huggingface.co/datasets/a/b", snippet="s"),
    ])

    dom = run.catalog.subdomains(run.catalog.load())[0]
    summ = run.discover(str(tmp_path / "S.csv"), domains=[dom], per_keyword=2,
                        max_total=5, enrich=False, quality_filter=True)

    # Only the HuggingFace dataset survived (the YouTube link was dropped).
    assert summ["new"] == 1


def test_discover_targets_reliable_engines_without_site_clause(tmp_path, monkeypatch):
    # The foundational engine fix: every query is routed to the reliable engines
    # (GitHub first) and carries no `site:` clause (the API engines ignore it).
    from cybersec_slm.sourcing import run
    from cybersec_slm.sourcing.search import Result

    seen: dict[str, list] = {"queries": [], "engines": []}

    def fake_search(query, *, pageno=1, engines=None, **k):
        seen["queries"].append(query)
        seen["engines"].append(engines)
        return [Result(title="T", link=f"https://example.com/{query}/{pageno}",
                       snippet="s")]

    monkeypatch.setattr(run, "searxng_search", fake_search)

    dom = run.catalog.subdomains(run.catalog.load())[0]
    run.discover(str(tmp_path / "S.csv"), domains=[dom], per_keyword=1, enrich=False)

    assert seen["queries"], "no searches were issued"
    assert all("site:" not in q for q in seen["queries"])
    assert all(e and e.split(",")[0] == "github" for e in seen["engines"])


def test_discover_fill_reaches_per_domain_target(tmp_path, monkeypatch):
    # Fill mode tops a lagging domain up to its per-domain valid target and stops.
    from cybersec_slm.sourcing import run
    from cybersec_slm.sourcing.search import Result

    n = {"i": 0}

    def fake_search(query, *, pageno=1, **k):
        n["i"] += 1
        return [Result(title="T", link=f"https://example.com/item{n['i']}", snippet="s")]

    monkeypatch.setattr(run, "searxng_search", fake_search)

    class _Enr:
        def __init__(self, **kw):
            pass

        def enrich(self, row):
            row["License"] = "MIT"                 # every candidate is commercial-ok
            return row

    monkeypatch.setattr(run, "Enricher", _Enr)

    dom = run.catalog.subdomains(run.catalog.load())[0]
    summ = run.discover(str(tmp_path / "S.csv"), domains=[dom], per_keyword=1,
                        target_per_domain=3, enrich=True)

    assert summ["new"] == 3
    assert summ["by_domain"][dom] == 3


def test_discover_fill_counts_only_commercial_valid(tmp_path, monkeypatch):
    # Only rows the license gate passes count toward the target; unknown/blocked
    # candidates are gathered and enriched but never appended or counted.
    import re

    import pandas as pd

    from cybersec_slm.sourcing import run
    from cybersec_slm.sourcing.search import Result

    n = {"i": 0}

    def fake_search(query, *, pageno=1, **k):
        n["i"] += 1
        return [Result(title="T", link=f"https://example.com/item{n['i']}", snippet="s")]

    monkeypatch.setattr(run, "searxng_search", fake_search)

    class _Enr:
        def __init__(self, **kw):
            pass

        def enrich(self, row):
            i = int(re.search(r"(\d+)$", row["Dataset Link"]).group(1))
            row["License"] = "MIT" if i % 2 == 0 else "GPL-3.0"   # copyleft is blocked
            return row

    monkeypatch.setattr(run, "Enricher", _Enr)

    csv_path = str(tmp_path / "S.csv")
    dom = run.catalog.subdomains(run.catalog.load())[0]
    summ = run.discover(csv_path, domains=[dom], per_keyword=1,
                        target_per_domain=2, enrich=True)

    assert summ["new"] == 2
    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False, encoding="utf-8")
    assert set(df["License"]) == {"MIT"}           # no GPL row was kept


def test_discover_fill_skips_already_satisfied_domain(tmp_path, monkeypatch):
    # A domain already at its target is skipped entirely - no searches are issued.
    import pandas as pd

    from cybersec_slm.sourcing import run
    from cybersec_slm.sourcing.search import Result

    csv_path = str(tmp_path / "S.csv")
    dom = run.catalog.subdomains(run.catalog.load())[0]
    pd.DataFrame([{"Sub-Domain": dom, "Dataset Link": f"https://x/{i}",
                   "License": "MIT"} for i in range(3)]
                 ).to_csv(csv_path, index=False, encoding="utf-8")

    called = {"n": 0}

    def fake_search(query, *, pageno=1, **k):
        called["n"] += 1
        return [Result(title="T", link=f"https://example.com/{called['n']}", snippet="s")]

    monkeypatch.setattr(run, "searxng_search", fake_search)

    class _Enr:
        def __init__(self, **kw):
            pass

        def enrich(self, row):
            row["License"] = "MIT"
            return row

    monkeypatch.setattr(run, "Enricher", _Enr)

    summ = run.discover(csv_path, domains=[dom], per_keyword=1,
                        target_per_domain=3, enrich=True)

    assert summ["new"] == 0
    assert called["n"] == 0                          # already satisfied -> never searched


def test_build_query_site_scopes_datasets_only():
    from cybersec_slm.sourcing.keywords import (
        QUERY_QUALIFIER,
        TEXT_QUERY_QUALIFIER,
        site_clause,
    )

    clause = site_clause()
    assert "site:huggingface.co" in clause and "site:github.com" in clause
    # datasets qualifier is the site-scoped one; text is not.
    assert QUERY_QUALIFIER != TEXT_QUERY_QUALIFIER


# ----------------------------------------------------------- search parsing ---


def test_parse_items_tolerates_missing_fields_and_no_items():
    # SearXNG JSON shape: {"results": [{url, title, content}, ...]}
    assert _parse_items({}) == []
    payload = {"results": [
        {"title": "T", "url": "https://x.com/a", "content": "line1\nline2"},
        {"title": "no link"},                       # dropped (no url)
    ]}
    items = _parse_items(payload)
    assert len(items) == 1
    assert items[0].link == "https://x.com/a"
    assert "\n" not in items[0].snippet
    # display_link falls back to the host when absent.
    assert items[0].display_link == "x.com"


class _CaptureClient:
    """A fake httpx.Client that records the params of the last GET."""

    def __init__(self, results=None):
        self.last_params = None
        self._results = results or []

    def get(self, endpoint, params=None, headers=None):
        self.last_params = params

        class _Resp:
            status_code = 200

            def json(_self):
                return {"results": self.results_}

            text = ""

        self.results_ = self._results
        return _Resp()


def test_searxng_search_forwards_engines_when_set():
    from cybersec_slm.sourcing.search import searxng_search

    client = _CaptureClient(results=[{"url": "https://github.com/a/b", "title": "t"}])
    searxng_search("q", client=client, engines="github,arxiv")
    assert client.last_params["engines"] == "github,arxiv"


def test_searxng_search_omits_engines_when_none():
    from cybersec_slm.sourcing.search import searxng_search

    client = _CaptureClient(results=[])
    searxng_search("q", client=client)
    assert "engines" not in client.last_params


# ------------------------------------------------------- rename a sub-domain ---
def test_rename_subdomain_relabels_only_matching_rows(tmp_path):
    csv_path = str(tmp_path / "Sources.csv")
    append_rows(csv_path, [
        build_row(Result(title="A", link="https://huggingface.co/datasets/a/x",
                         snippet="s"), "Cloud Security", today="01/01/2026"),
        build_row(Result(title="B", link="https://github.com/b/y", snippet="s"),
                  "Cloud Security", today="01/01/2026"),
        build_row(Result(title="C", link="https://example.com/c", snippet="s"),
                  "Network Security", today="01/01/2026"),
    ])

    assert rename_subdomain(csv_path, "Cloud Security", "Cloud & Platform") == 2

    import pandas as pd
    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
    assert sorted(df["Sub-Domain"]) == ["Cloud & Platform", "Cloud & Platform",
                                        "Network Security"]
    # Renaming must not disturb any other column.
    assert set(df["Dataset Link"]) == {"https://huggingface.co/datasets/a/x",
                                       "https://github.com/b/y",
                                       "https://example.com/c"}


def test_rename_subdomain_no_op_cases(tmp_path):
    csv_path = str(tmp_path / "Sources.csv")
    append_rows(csv_path, [
        build_row(Result(title="A", link="https://example.com/a", snippet="s"),
                  "Cloud Security", today="01/01/2026"),
    ])
    assert rename_subdomain(csv_path, "Cloud Security", "Cloud Security") == 0
    assert rename_subdomain(csv_path, "Nope", "Other") == 0
    assert rename_subdomain(csv_path, "", "Other") == 0
    assert rename_subdomain(csv_path, "Cloud Security", "") == 0
    assert rename_subdomain(str(tmp_path / "missing.csv"), "a", "b") == 0


# --------------------------------------------------- manually-added catalog row -
def test_build_manual_row_has_the_catalog_schema_and_infers_from_the_link():
    row = build_manual_row(name="darkknight25", subdomain="Cloud Security",
                           link="https://huggingface.co/datasets/dk/cloud",
                           description="Cloud vulns", license="MIT",
                           today="18/06/2026")
    assert set(row) == set(SHEET_COLUMNS)          # same shape as a discovered row
    assert row["Name"] == "darkknight25"
    assert row["Sub-Domain"] == "Cloud Security"
    assert row["Dataset Link"] == "https://huggingface.co/datasets/dk/cloud"
    assert row["Description"] == "Cloud vulns"
    assert row["License"] == "MIT"
    assert row["Category"] == "Dataset"            # inferred from the HF link
    assert row["Date Added"] == "18/06/2026"
    assert row["Is Synthetic?"] == ""


def test_build_manual_row_explicit_category_and_format_win_over_inference():
    row = build_manual_row(name="n", subdomain="d",
                           link="https://github.com/o/r",
                           category="Dataset", original_format="CSV")
    assert row["Category"] == "Dataset"            # inference would say Repository
    assert row["Original Format"] == "CSV"


def test_build_manual_row_marks_synthetic_and_fills_extra_columns():
    row = build_manual_row(name="n", subdomain="d", link="https://x.test/f.jsonl",
                           is_synthetic=True,
                           extra={"Total Lines": "1200", "Author": "me",
                                  "Tags": "  ", "Bogus Column": "ignored"})
    assert row["Is Synthetic?"] == "Yes"
    assert row["Total Lines"] == "1200"
    assert row["Author"] == "me"
    assert row["Tags"] == ""                       # blank extras are not written
    assert "Bogus Column" not in row               # unknown keys cannot widen it


def test_build_manual_row_requires_name_subdomain_and_link():
    import pytest
    for kwargs in ({"name": "", "subdomain": "d", "link": "https://x.test"},
                   {"name": "n", "subdomain": "  ", "link": "https://x.test"},
                   {"name": "n", "subdomain": "d", "link": ""}):
        with pytest.raises(ValueError, match="missing required field"):
            build_manual_row(**kwargs)


def test_manual_row_appends_and_is_deduped_like_a_discovered_one(tmp_path):
    csv_path = str(tmp_path / "Sources.csv")
    row = build_manual_row(name="n", subdomain="Cloud Security",
                           link="https://huggingface.co/datasets/a/x")
    append_rows(csv_path, [row])
    # The link is now visible to the dedup path discovery uses, in normalized form.
    assert normalize_url("http://www.huggingface.co/datasets/a/x/") in \
        existing_links(csv_path)
