"""Offline tests for the sourcing primitives — pure logic, no network/credentials.

The engine orchestration itself is covered by ``test_engine.py`` and
``test_discovery_funnel.py``; this file pins the small, reusable pieces the engine
composes (keywords/taxonomy, classify, row builder, catalog I/O, SearXNG parsing).
"""

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
    # Breadth (many distinct keywords) is the main lever for wider per-sub-domain
    # coverage, since single-page API backends cap depth per keyword.
    for domain, words in kw.DOMAIN_KEYWORDS.items():
        assert len(words) >= 12, f"{domain} has too few keywords ({len(words)})"
        assert len(words) == len(set(words)), f"{domain} has duplicate keywords"


def test_default_engines_are_github_first_and_reliable():
    ds = kw.default_engines()
    assert ds.split(",")[0] == "github"            # highest commercial-valid yield
    for eng in ("openairedatasets", "arxiv", "semantic scholar"):
        assert eng in ds
    # None of the rate-limited general web engines are in the default set.
    for dead in ("google", "duckduckgo", "brave", "startpage", "bing"):
        assert dead not in ds


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
    assert refine_domain("Internal Audit", "Some title", "generic text") == "Internal Audit"


def test_refine_domain_reassigns_on_stronger_signal():
    domain = refine_domain(
        "Internal Audit",
        "Screening politically exposed persons",
        "customer due diligence and sanctions screening for money laundering risk")
    assert domain == "AML-KYC"


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

    assert append_rows(csv_path, rows) == 1
    with open(csv_path, encoding="utf-8") as f:
        header, *data = list(_csv.reader(f))
    assert header == list(SHEET_COLUMNS)
    assert len(data) == 1
    assert "nan" not in [c.strip().lower() for c in data[0]]

    links = existing_links(csv_path)
    assert normalize_url("https://huggingface.co/datasets/foo/bar") in links
    assert existing_links(str(tmp_path / "nope.csv")) == set()


def test_append_rows_unions_new_columns_into_legacy_file(tmp_path):
    import pandas as pd

    csv_path = str(tmp_path / "Sources.csv")
    legacy = ["Name", "Sub-Domain", "Dataset Link", "License"]
    pd.DataFrame([{"Name": "Old", "Sub-Domain": "D",
                   "Dataset Link": "https://a", "License": "MIT"}],
                 columns=legacy).to_csv(csv_path, index=False, encoding="utf-8")

    append_rows(csv_path, [{"Name": "New", "Sub-Domain": "D",
                            "Dataset Link": "https://b", "Author": "octo"}])
    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False, encoding="utf-8")
    assert "Author" in df.columns
    assert list(df.columns[:4]) == legacy
    assert df.iloc[0]["Author"] == ""
    assert df.iloc[1]["Author"] == "octo"


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
    assert counts["Cryptography"] == 2
    assert counts["Network Security"] == 1


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

    assert delete_rows(csv_path, subdomains=["Network Security"]) == 2
    links = existing_links(csv_path)
    assert normalize_url("https://huggingface.co/datasets/a/x") in links
    assert len(links) == 1

    assert delete_rows(csv_path, links=["http://www.huggingface.co/datasets/a/x/"]) == 1
    assert existing_links(csv_path) == set()

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

    assert delete_rows(csv_path, positions=[2, 3]) == 2
    links = existing_links(csv_path)
    assert normalize_url("https://example.com/A") in links
    assert normalize_url("https://example.com/D") in links
    assert len(links) == 2

    assert delete_rows(csv_path, positions=[99]) == 0


# ------------------------------------------------------- engine routing (kw) ---


def test_site_keywords_route_to_engines_that_honour_the_operator(monkeypatch):
    """A ``site:`` dork must not run on github/arxiv: they *ignore* the operator and
    answer the bare terms, returning confident results from the wrong host."""
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "ubi")
    assert kw.SITE_ENGINES, "the ubi profile declares site-honouring engines"

    plain = kw.engines_for_keyword("anti money laundering dataset")
    dork = kw.engines_for_keyword('site:unionbankofindia.bank.in "Basel III"')

    assert plain.split(",")[0] == "github"
    assert dork == ",".join(kw.SITE_ENGINES)
    assert "github" not in dork


def test_site_routing_is_a_no_op_for_a_profile_without_site_engines(monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_PROFILE", "cybersec")
    assert not kw.SITE_ENGINES
    assert kw.engines_for_keyword("site:example.com x") == kw.default_engines()


def test_build_query_site_scopes():
    from cybersec_slm.sourcing.keywords import site_clause

    clause = site_clause()
    assert "site:huggingface.co" in clause and "site:github.com" in clause


# ----------------------------------------------------------- search parsing ---


def test_parse_items_tolerates_missing_fields_and_no_items():
    assert _parse_items({}) == []
    payload = {"results": [
        {"title": "T", "url": "https://x.com/a", "content": "line1\nline2"},
        {"title": "no link"},
    ]}
    items = _parse_items(payload)
    assert len(items) == 1
    assert items[0].link == "https://x.com/a"
    assert "\n" not in items[0].snippet
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
    assert set(row) == set(SHEET_COLUMNS)
    assert row["Name"] == "darkknight25"
    assert row["Sub-Domain"] == "Cloud Security"
    assert row["Dataset Link"] == "https://huggingface.co/datasets/dk/cloud"
    assert row["Description"] == "Cloud vulns"
    assert row["License"] == "MIT"
    assert row["Category"] == "Dataset"
    assert row["Date Added"] == "18/06/2026"
    assert row["Is Synthetic?"] == ""


def test_build_manual_row_explicit_category_and_format_win_over_inference():
    row = build_manual_row(name="n", subdomain="d",
                           link="https://github.com/o/r",
                           category="Dataset", original_format="CSV")
    assert row["Category"] == "Dataset"
    assert row["Original Format"] == "CSV"


def test_build_manual_row_marks_synthetic_and_fills_extra_columns():
    row = build_manual_row(name="n", subdomain="d", link="https://x.test/f.jsonl",
                           is_synthetic=True,
                           extra={"Total Lines": "1200", "Author": "me",
                                  "Tags": "  ", "Bogus Column": "ignored"})
    assert row["Is Synthetic?"] == "Yes"
    assert row["Total Lines"] == "1200"
    assert row["Author"] == "me"
    assert row["Tags"] == ""
    assert "Bogus Column" not in row


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
    assert normalize_url("http://www.huggingface.co/datasets/a/x/") in \
        existing_links(csv_path)
