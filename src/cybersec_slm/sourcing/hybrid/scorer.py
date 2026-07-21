"""
scorer.py – Relevance scoring for candidate rows.

Every row from every backend passes through relevance_score() before being
accepted into the catalog. Rows below config.quality.min_relevance_score
are silently dropped — this is the primary mechanism that prevents off-topic
results (medical CT scans, drone security, COVID repos, etc.) from polluting
the corpus.

Score components (all normalised 0–1):
  keyword_score  (weight 0.40) – fraction of domain_signals found in text
  host_score     (weight 0.30) – trust level of the source host
  country_score  (weight 0.30) – alignment with the config's country_bias

Final score = 0.40*keyword + 0.30*host + 0.30*country  (range 0–1)
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from .config import HybridConfig

# Hosts with known, high-quality, openly-licensed content
_TRUSTED_HOSTS = {
    "huggingface.co", "github.com", "gitlab.com", "arxiv.org",
    "zenodo.org", "kaggle.com",
    # Indian government open-data portals
    "data.gov.in", "indiacode.nic.in", "egazette.gov.in",
    "rbi.org.in", "sebi.gov.in", "fiuindia.gov.in",
    "mca.gov.in", "npci.org.in", "ibbi.gov.in",
    "irdai.gov.in", "enforcementdirectorate.gov.in",
    "drt.gov.in", "nclt.gov.in",
    # Indian banks (own content)
    "unionbankofindia.bank.in", "sbi.co.in",
    "pnbindia.in", "bankofbaroda.in", "canarabank.com",
    "hdfcbank.com", "icicibank.com", "axisbank.com",
}

# Hosts that are junk regardless of content
_JUNK_HOSTS = {
    "pinterest.com", "facebook.com", "twitter.com", "x.com",
    "youtube.com", "reddit.com", "instagram.com", "tiktok.com",
    "linkedin.com", "quora.com", "medium.com", "substack.com",
}


def _bare_host(url: str) -> str:
    try:
        netloc = urlparse(url).netloc
        return netloc.lower().removeprefix("www.").split(":")[0]
    except Exception:
        return ""


def _text(name: str, description: str) -> str:
    return f"{name} {description}".lower()


def keyword_score(name: str, description: str, config: HybridConfig) -> float:
    """Fraction of domain_signals found in the row's text (0–1)."""
    signals = config.quality.domain_signals
    if not signals:
        return 0.5  # neutral when no signals defined
    text = _text(name, description)
    hits = sum(1 for s in signals if re.search(r"\b" + re.escape(s) + r"\b", text))
    return min(hits / max(len(signals) * 0.15, 1), 1.0)


def host_score(url: str, config: HybridConfig) -> float:
    """Trust level of the source host (0–1)."""
    host = _bare_host(url)
    if not host:
        return 0.0
    # Always-junk
    if any(host == j or host.endswith("." + j) for j in _JUNK_HOSTS):
        return 0.0
    # Explicitly trusted by config
    if any(host == t or host.endswith("." + t) for t in config.quality.trusted_hosts):
        return 1.0
    # Globally trusted
    if any(host == t or host.endswith("." + t) for t in _TRUSTED_HOSTS):
        return 1.0
    # Explicitly blocked
    if any(host == b or host.endswith("." + b) for b in config.quality.blocked_hosts):
        return 0.0
    return 0.5  # unknown host: neutral


def country_score(country: str, name: str, description: str,
                  config: HybridConfig) -> float:
    """Alignment of the row's country with the config's primary country bias (0–1)."""
    primary = config.primary_country
    bias = config.country_bias.get(primary, 0.5)

    if country == primary:
        return 1.0
    # Try to infer from text signals
    signals = config.api_backends.get("huggingface", None)
    signal_kws: list[str] = []
    for bc in config.api_backends.values():
        signal_kws.extend(bc.country_signal_keywords)
    if signal_kws:
        text = _text(name, description)
        if any(k in text for k in signal_kws):
            return 0.8  # text suggests primary country
    # Neutral / other country
    return 0.3 * bias


def relevance_score(name: str, description: str, url: str,
                    country: str, config: HybridConfig) -> float:
    """Composite relevance score (0–1). Rows below min_relevance_score are rejected."""
    ks = keyword_score(name, description, config)
    hs = host_score(url, config)
    cs = country_score(country, name, description, config)
    return 0.40 * ks + 0.30 * hs + 0.30 * cs


def has_off_topic_signals(name: str, description: str, config: HybridConfig) -> bool:
    """True when the row's text contains an off-topic signal word from config."""
    if not config.quality.off_topic_signals:
        return False
    text = _text(name, description)
    return any(s in text for s in config.quality.off_topic_signals)


def is_listing_page(url: str) -> bool:
    """True when the URL looks like a search/tag/listing page."""
    _LISTING = {"search", "tag", "tags", "topic", "topics", "category",
                "categories", "label", "labels"}
    try:
        p = urlparse(url)
        segments = {s for s in p.path.lower().split("/") if s}
        if segments & _LISTING:
            return True
        # bare ?q= style search URL
        if "q=" in p.query:
            return True
    except Exception:
        pass
    return False


def passes_quality(name: str, description: str, url: str,
                   country: str, config: HybridConfig) -> tuple[bool, str]:
    """
    Returns (True, "") if the row passes quality gates, else (False, reason).
    """
    q = config.quality

    if q.reject_listing_pages and is_listing_page(url):
        return False, "listing page"

    if has_off_topic_signals(name, description, config):
        return False, "off-topic signal"

    if q.reject_off_topic_hosts:
        host = _bare_host(url)
        if any(host == j or host.endswith("." + j) for j in _JUNK_HOSTS):
            return False, f"junk host ({host})"
        if any(host == b or host.endswith("." + b) for b in q.blocked_hosts):
            return False, f"blocked host ({host})"

    score = relevance_score(name, description, url, country, config)
    if score < q.min_relevance_score:
        return False, f"relevance too low ({score:.2f} < {q.min_relevance_score})"

    return True, ""
