#!/usr/bin/env python3
"""Infer sheet fields that are knowable from a search result alone."""

from __future__ import annotations

from urllib.parse import urlparse


def infer_category_and_format(url: str) -> tuple[str, str]:
    low = (url or "").lower()
    host = urlparse(low).netloc

    if low.endswith(".pdf"):
        return "Document", "PDF"
    if low.endswith((".csv", ".json", ".jsonl", ".parquet", ".xlsx", ".txt")):
        fmt = low.rsplit(".", 1)[-1].upper()
        fmt = {"JSONL": "JSONL", "XLSX": "XLSX"}.get(fmt, fmt)
        return "Dataset", fmt

    if low.endswith((".rss", ".atom", ".xml")) or "/feed" in low or "/rss" in low:
        fmt = "XML" if low.endswith(".xml") else ("RSS" if "rss" in low else "ATOM")
        return "Feed", fmt

    if host.startswith("api.") or "/api/" in low or "graphql" in low or low.endswith(".json"):
        return "API", "JSON"

    if "huggingface.co" in host and "/datasets/" in low:
        return "Dataset", ""
    if "kaggle.com" in host and "/datasets/" in low:
        return "Dataset", ""
    if "github.com" in host or "gitlab.com" in host or "raw.githubusercontent" in host:
        return "Repository", ""
    if "arxiv.org" in host:
        return "Document", "PDF"
    if "zenodo.org" in host or "figshare.com" in host or "data.gov" in host:
        return "Dataset", ""
    return "Website", "HTML"


def _score(text: str, vocab: set[str]) -> int:
    return sum(1 for term in vocab if term in text)


def build_domain_vocab(cat: dict | None = None) -> dict[str, set[str]]:
    """Distinctive tie-break terms per sub-domain, from the live catalog.

    Prefers each sub-domain's explicit ``vocab`` field (the historical
    ``DOMAIN_VOCAB`` short terms for the 12 built-ins, or whatever a user has set
    for a custom sub-domain); falls back to a coarser vocab derived from the
    sub-domain's own search keywords (``datasets`` + ``text``) when no explicit
    ``vocab`` is set, so a newly-added sub-domain still gets *some* tie-break
    signal instead of none.
    """
    from . import catalog as _catalog
    cat = cat if cat is not None else _catalog.load()
    return {name: set(spec.get("vocab") or _catalog.keywords_for(name, "both", cat))
            for name, spec in cat.items()}


def refine_domain(default_domain: str, title: str, snippet: str,
                  vocab: dict[str, set[str]] | None = None) -> str:
    """Pick the best-matching sub-domain for a search result's title/snippet.

    ``vocab`` (``{sub-domain: {term, ...}}``) should be computed once per
    discovery run via :func:`build_domain_vocab` and passed in by the caller;
    when omitted it is computed here (convenient for direct/one-off calls, but
    wasteful in a per-result loop).
    """
    vocab = vocab if vocab is not None else build_domain_vocab()
    text = f"{title} {snippet}".lower()
    base = _score(text, vocab.get(default_domain, set()))
    best_domain, best_score = default_domain, base
    for domain, v in vocab.items():
        if domain == default_domain:
            continue
        s = _score(text, v)
        if s > best_score:
            best_domain, best_score = domain, s
    return best_domain
