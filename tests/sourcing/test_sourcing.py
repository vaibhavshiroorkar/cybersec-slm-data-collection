"""Offline tests for the sourcing stage — pure logic, no network/credentials."""

from cybersec_slm.sourcing import keywords as kw
from cybersec_slm.sourcing.classify import infer_category_and_format, refine_domain
from cybersec_slm.sourcing.row import SHEET_COLUMNS, build_row, row_to_list
from cybersec_slm.sourcing.search import Result, _parse_items
from cybersec_slm.sourcing.sheet import append_rows, existing_links, normalize_url

# ----------------------------------------------------------------- keywords ---


def test_every_domain_has_keywords_and_vocab():
    assert kw.DOMAIN_KEYWORDS, "no domains configured"
    for domain, words in kw.DOMAIN_KEYWORDS.items():
        assert words, f"{domain} has no keywords"
        assert domain in kw.DOMAIN_VOCAB, f"{domain} missing vocab"
        assert kw.DOMAIN_VOCAB[domain], f"{domain} vocab empty"


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
    # Searched under Threat Intelligence but the text screams malware.
    domain = refine_domain(
        "Threat Intelligence",
        "Ransomware sandbox samples",
        "Labeled malware ransomware PE binary samples for reverse engineering")
    assert domain == "Malware Analysis"


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
    # Extraction/cleaning-dependent fields stay blank.
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
    assert header == list(SHEET_COLUMNS)              # 19 cols, canonical order
    assert len(data) == 1
    # Unfilled cells are blank strings, never the literal "nan".
    assert "nan" not in [c.strip().lower() for c in data[0]]

    # existing_links recognizes the appended link (normalized).
    links = existing_links(csv_path)
    assert normalize_url("https://huggingface.co/datasets/foo/bar") in links

    # A second append with the same link still writes (dedup is the caller's job),
    # and existing_links on a missing file is just empty.
    assert existing_links(str(tmp_path / "nope.csv")) == set()


# ----------------------------------------------------------- search parsing ---


def test_parse_items_tolerates_missing_fields_and_no_items():
    assert _parse_items({}) == []
    payload = {"items": [
        {"title": "T", "link": "https://x.com/a", "snippet": "line1\nline2"},
        {"title": "no link"},                       # dropped (no link)
    ]}
    items = _parse_items(payload)
    assert len(items) == 1
    assert items[0].link == "https://x.com/a"
    assert "\n" not in items[0].snippet
