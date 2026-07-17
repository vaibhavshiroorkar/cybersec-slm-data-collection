#!/usr/bin/env python3
"""Fetch an RSS or Atom feed into records.

Regulators publish as feeds. RBI's circulars and press releases are an RSS URL,
and it was the one shape this pipeline could not read: ``feed`` meant JSON only
(``scrape_feed`` calls ``orjson.loads`` on the body), ``xml`` meant MITRE CWE only
(hardcoded namespace and URL), and an ``.rss``/``.xml``/``rss.aspx`` URL matched
neither. It fell through to ``fetch_url``, which downloaded the feed as an opaque
file and produced no records and no error: the worst outcome, because the source
looked catalogued and fetched while contributing nothing.

Stdlib ``xml.etree`` rather than feedparser: RSS 2.0 and Atom differ in about six
element names between them, this needs the title, link, summary and date, and a
dependency that parses a hundred dialects earns nothing here. It is also one less
untrusted-input parser to keep patched, and every byte here is untrusted.

A feed item is a headline and a summary, not a document: the link points at the
real thing. That is honest metadata and often the only machine-readable index a
regulator offers, so the item is the record and the crawler is what would follow
the link.
"""

from __future__ import annotations

import os
import re
from urllib.parse import urlparse
from xml.etree import ElementTree

from ..core import logger, sha256_file
from .common import ONE_MB, category_of, http_get

BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))), "data", "raw")

_ATOM_NS = "{http://www.w3.org/2005/Atom}"

# URL shapes that mean "this is a feed". Narrow enough that it cannot swallow a
# fetchable file (it runs before the url/github fallback), wide enough for what
# publishers actually serve, which is the harder half: a first cut matched
# /rss.xml and /feed/ and missed every one of RBI's real feeds, because they are
# named notifications_rss.xml and Publication_rss.xml. "rss" is a suffix on a
# name far more often than it is a path segment.
_FEED_RE = re.compile(
    r"(?:^|/|[._-])(?:rss|atom)\.(?:xml|aspx|php)$"     # /notifications_rss.xml
    r"|(?:^|/)(?:rss|atom|feed)(?:\.aspx|\.xml|\.php|/|$)"   # /rss.aspx, /feed/
    r"|\.(?:rss|atom)$"                                 # /x.rss, /x.atom
    r"|(?:^|/|[._-])feed\.xml$",                        # /blog_feed.xml
    re.IGNORECASE)


class FeedError(RuntimeError):
    """Raised when a body is not a feed this can read."""


def _text(el) -> str:
    return "".join(el.itertext()).strip() if el is not None else ""


def _first(item, *names):
    """The first child matching any of ``names``, plain or Atom-namespaced."""
    for name in names:
        found = item.find(name)
        if found is None:
            found = item.find(f"{_ATOM_NS}{name}")
        if found is not None:
            return found
    return None


def _link_of(item) -> str:
    """The item's link. RSS puts it in the text, Atom in a href attribute."""
    el = _first(item, "link")
    if el is None:
        return ""
    return (_text(el) or el.get("href") or "").strip()


def parse(body) -> list[dict]:
    """Parse an RSS or Atom body into records.

    Raises :class:`FeedError` for anything that is not a readable feed, rather
    than returning nothing: an empty list would be indistinguishable from a feed
    with no items, and the run would record a source that produced nothing for no
    stated reason. A dead feed URL commonly answers 200 with a login or error page.
    """
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    body = (body or "").strip()
    if not body:
        raise FeedError("empty response")

    # Sniff HTML before parsing, not after. An HTML page rarely parses as XML, so
    # checking the root tag only catches the well-formed minority and everything
    # else surfaces as "not parseable as XML", which sends the reader looking for
    # a broken feed instead of the truth: this URL is a web page. That is the
    # common case, not an edge one. rbi.org.in/Scripts/rss.aspx, the obvious URL
    # for RBI's feed, is exactly this: an HTML page listing the real feeds.
    if re.match(r"<!doctype\s+html|<html[\s>]", body[:200], re.IGNORECASE):
        raise FeedError("the URL returned HTML, not a feed (a feed index page or "
                        "an error page?)")
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError as e:
        head = body[:80].replace("\n", " ")
        raise FeedError(f"not parseable as XML ({e}); body starts {head!r}") from e

    tag = root.tag.lower()
    if tag.endswith("html"):
        raise FeedError("the URL returned HTML, not a feed")

    items = root.findall(".//item") or root.findall(f".//{_ATOM_NS}entry")
    if not items and not (tag.endswith("rss") or tag.endswith("feed")
                          or root.find(".//channel") is not None):
        raise FeedError(f"root element {root.tag!r} is neither rss nor atom")

    out: list[dict] = []
    for item in items:
        title = _text(_first(item, "title"))
        summary = _text(_first(item, "description", "summary", "content"))
        published = _text(_first(item, "pubDate", "published", "updated"))
        link = _link_of(item)
        if not (title or summary):
            continue                 # an item with neither is not a record
        out.append({
            "title": title,
            "link": link,
            "summary": summary,
            "published": published,
            "guid": _text(_first(item, "guid", "id")),
            # The prose the cleaning stage reads. Title and summary together,
            # because a headline alone is under the length floor and would be
            # dropped, taking the item's only content with it.
            "text": f"{title}\n\n{summary}".strip(),
        })
    return out


def is_feed_url(url: str) -> bool:
    """Whether ``url`` looks like an RSS/Atom feed.

    Checked before the generic file/repo fallback, so it stays narrow: a false
    positive makes a fetchable file unfetchable.
    """
    low = (url or "").strip().lower()
    if not low:
        return False
    if low.endswith(".xml.zip") or "cwe.mitre.org" in low:
        return False                 # MITRE CWE has its own fetcher
    p = urlparse(low if "://" in low else "//" + low)
    return bool(_FEED_RE.search(p.path)) or bool(_FEED_RE.search(low))


def scrape_rss(domain: str, slug: str, title: str, lic: str, url: str, log) -> None:
    """Fetch ``url`` as a feed and write one JSONL record per item."""
    folder = os.path.join(BASE, domain, slug)
    os.makedirs(folder, exist_ok=True)
    logger.info(f"=== RSS: {title} ===")

    resp = http_get(url, timeout=240)
    items = parse(resp.content)

    out = os.path.join(folder, slug + ".jsonl")
    with open(out, "w", encoding="utf-8") as f:
        from ..core import json_dumps
        for item in items:
            # source/url/license are what cleaning and normalize read as
            # provenance; `source` is the slug, never the description.
            f.write(json_dumps({**item, "source": slug,
                                "url": item.get("link") or url,
                                "license": lic}) + "\n")
    size = os.path.getsize(out)
    logger.info(f"  {len(items):,} item(s), {size / ONE_MB:.2f} MB")
    log.record(kind="rss", name=slug, category=category_of("feed"), domain=domain,
               description=title, source_url=url, origin_format="xml",
               orig_mb=round(len(resp.content) / ONE_MB, 1),
               jsonl_mb=round(size / ONE_MB, 1), rows=len(items),
               sha256=sha256_file(out), license=lic, status="ok")
