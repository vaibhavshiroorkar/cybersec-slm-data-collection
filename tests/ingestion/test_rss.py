"""RSS and Atom feeds: parsing them, and routing a feed URL to the right fetcher.

RBI publishes its circulars and press releases as RSS. Nothing here could read a
feed: `feed` meant JSON only, `xml` meant MITRE CWE only, and an .rss/.xml URL
matched neither, so it fell through to fetch_url and was downloaded as an opaque
file that produced no records and no error.
"""

import pytest

from cybersec_slm.ingestion import rss

_RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <title>RBI Press Releases</title>
  <item>
    <title>Master Direction on KYC</title>
    <link>https://rbi.org.in/Scripts/BS_ViewMasDirections.aspx?id=11566</link>
    <description>Amendments to the Master Direction on Know Your Customer.</description>
    <pubDate>Mon, 14 Jul 2026 10:00:00 GMT</pubDate>
    <guid>https://rbi.org.in/id/11566</guid>
  </item>
  <item>
    <title>Basel III Capital Regulations</title>
    <link>https://rbi.org.in/Scripts/BS_ViewMasDirections.aspx?id=11567</link>
    <description>Revised guidelines on capital adequacy.</description>
  </item>
</channel></rss>"""

_ATOM = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Example</title>
  <entry>
    <title>Risk Management Policy</title>
    <link href="https://example.test/a"/>
    <summary>An entry summary about operational risk.</summary>
    <updated>2026-07-14T10:00:00Z</updated>
    <id>tag:example,2026:a</id>
  </entry>
</feed>"""


# ------------------------------------------------------------------ parse -----
def test_an_rss_feed_yields_one_record_per_item():
    items = rss.parse(_RSS)

    assert len(items) == 2
    assert items[0]["title"] == "Master Direction on KYC"
    assert items[0]["link"].endswith("id=11566")
    assert "Know Your Customer" in items[0]["summary"]
    assert items[0]["published"].startswith("Mon, 14 Jul 2026")


def test_an_atom_feed_yields_one_record_per_entry():
    """Atom nests the link in an href attribute and calls the body a summary."""
    items = rss.parse(_ATOM)

    assert len(items) == 1
    assert items[0]["title"] == "Risk Management Policy"
    assert items[0]["link"] == "https://example.test/a"
    assert "operational risk" in items[0]["summary"]


def test_an_item_missing_optional_fields_still_parses():
    items = rss.parse(_RSS)

    assert items[1]["published"] == ""      # no pubDate on the second item
    assert items[1]["title"]


def test_the_text_field_carries_the_prose_the_cleaner_reads():
    """Without `text` the cleaning stage has nothing to clean and drops the lot."""
    for item in rss.parse(_RSS):
        assert item["text"]
        assert item["title"] in item["text"]


def test_an_empty_feed_is_empty_not_an_error():
    assert rss.parse('<rss version="2.0"><channel><title>x</title></channel></rss>') == []


def test_malformed_xml_raises_rather_than_returning_nothing():
    """Silently returning [] would look identical to a feed with no items, and the
    run would record a source that produced nothing for no stated reason."""
    with pytest.raises(rss.FeedError):
        rss.parse("<rss><channel><item><title>unclosed")


def test_html_served_instead_of_a_feed_is_refused():
    """A dead feed URL commonly returns a login or error page with 200."""
    with pytest.raises(rss.FeedError):
        rss.parse("<!DOCTYPE html><html><body>Not found</body></html>")


def test_parse_accepts_bytes_as_httpx_returns_them():
    assert len(rss.parse(_RSS.encode("utf-8"))) == 2


# ------------------------------------------------------------- is_feed_url ----
@pytest.mark.parametrize("url", [
    "https://rbi.org.in/Scripts/rss.aspx",
    "https://blog.test/feed.xml",
    "https://blog.test/rss",
    "https://blog.test/feed/",
    "https://blog.test/index.atom",
    "https://blog.test/atom.xml",
])
def test_a_feed_url_is_recognized(url):
    assert rss.is_feed_url(url)


@pytest.mark.parametrize("url", [
    "https://github.com/org/repo",
    "https://huggingface.co/datasets/a/b",
    "https://example.test/data.csv",
    "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
])
def test_a_non_feed_url_is_not_mistaken_for_one(url):
    assert not rss.is_feed_url(url)


def test_the_rbi_feed_is_the_case_this_exists_for():
    assert rss.is_feed_url("https://rbi.org.in/Scripts/rss.aspx")


# --------------------------------------------------------------- routing ------
def test_a_feed_url_is_routed_to_the_rss_kind(tmp_path):
    """The gap: an .rss/.xml URL matched no kind and fell through to `url`, which
    downloaded the feed as an opaque file and produced no records."""
    from cybersec_slm.ingestion import sources as srcs

    csv = tmp_path / "Sources.csv"
    csv.write_text(
        "Name,Sub-Domain,Description,Dataset Link,License\n"
        "rbi-feed,AML-KYC,RBI press releases,https://rbi.org.in/Scripts/rss.aspx,"
        "Government of India\n", encoding="utf-8")

    [d] = srcs.load_descriptors(str(csv), order_by_size=False)

    assert d["kind"] == "rss"
    assert d["url"] == "https://rbi.org.in/Scripts/rss.aspx"


def test_the_cwe_xml_zip_still_routes_to_its_own_fetcher(tmp_path):
    """rss must not steal the kinds that already work."""
    from cybersec_slm.ingestion import sources as srcs

    csv = tmp_path / "Sources.csv"
    csv.write_text(
        "Name,Sub-Domain,Description,Dataset Link,License\n"
        "cwe,AML-KYC,MITRE CWE,https://cwe.mitre.org/data/xml/cwec_latest.xml.zip,"
        "MITRE\n", encoding="utf-8")

    [d] = srcs.load_descriptors(str(csv), order_by_size=False)

    assert d["kind"] == "xml"


# ---------------------------------------------------------------- fetch -------
def test_fetching_a_feed_writes_one_jsonl_record_per_item(tmp_path, monkeypatch):
    class _Resp:
        content = _RSS.encode("utf-8")

    monkeypatch.setattr(rss, "http_get", lambda url, timeout=None: _Resp())
    monkeypatch.setattr(rss, "BASE", str(tmp_path))

    class _Log:
        def __init__(self):
            self.rows = []

        def record(self, **kw):
            self.rows.append(kw)

    log = _Log()
    rss.scrape_rss("AML-KYC", "rbi-feed", "RBI Press Releases",
                   "Government of India", "https://rbi.org.in/Scripts/rss.aspx", log)

    import json
    out = tmp_path / "AML-KYC" / "rbi-feed" / "rbi-feed.jsonl"
    recs = [json.loads(x) for x in out.read_text(encoding="utf-8").splitlines()]
    assert len(recs) == 2
    for r in recs:
        # The provenance the cleaner and normalize both require.
        assert {"source", "url", "license", "text"} <= set(r)
        assert r["source"] == "rbi-feed"
    [row] = log.rows
    assert row["kind"] == "rss" and row["rows"] == 2 and row["status"] == "ok"
