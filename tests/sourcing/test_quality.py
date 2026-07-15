"""Tests for the discovery result quality filter (sourcing.quality)."""

from cybersec_slm.sourcing.quality import passes
from cybersec_slm.sourcing.search import Result


def _r(link: str, title: str = "t", snippet: str = "s") -> Result:
    return Result(title=title, link=link, snippet=snippet)


def test_keeps_licensable_dataset_and_repo_hosts():
    keep = [
        "https://huggingface.co/datasets/foo/bar",
        "https://github.com/foo/bar",
        "https://gitlab.com/foo/bar",
        "https://www.kaggle.com/datasets/foo/bar",
        "https://zenodo.org/record/12345",
        "https://arxiv.org/abs/2401.00001",
        "https://catalog.data.gov/dataset/foo",
        "https://archive.ics.uci.edu/dataset/1/foo",
    ]
    for link in keep:
        assert passes(_r(link)) is True, link


def test_drops_social_and_junk_hosts():
    drop = [
        "https://www.pinterest.com/pin/123",
        "https://facebook.com/somepage",
        "https://twitter.com/someuser",
        "https://x.com/someuser",
        "https://www.youtube.com/watch?v=abc",
        "https://www.reddit.com/r/netsec/comments/x",
    ]
    for link in drop:
        assert passes(_r(link)) is False, link


def test_drops_listing_and_search_landing_pages():
    drop = [
        "https://example.com/search?q=malware+dataset",
        "https://example.com/tags/security",
        "https://example.com/topics/cyber",
        "https://example.com/?q=dataset",
    ]
    for link in drop:
        assert passes(_r(link)) is False, link


def test_keeps_ordinary_dataset_or_doc_pages():
    assert passes(_r("https://example.com/data/threats.csv")) is True
    assert passes(_r("https://someblog.io/how-tls-works")) is True


def test_drops_empty_or_hostless_links():
    assert passes(_r("")) is False
    assert passes(_r("not a url")) is False


def test_github_search_and_topics_landing_dropped_even_on_licensable_host():
    # A GitHub *search*/topics listing is not a repo; drop it despite the host.
    assert passes(_r("https://github.com/search?q=malware")) is False
    assert passes(_r("https://github.com/topics/security")) is False
