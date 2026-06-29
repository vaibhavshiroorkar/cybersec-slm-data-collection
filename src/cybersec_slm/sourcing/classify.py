#!/usr/bin/env python3
"""Infer sheet fields that are knowable from a search result alone."""

from __future__ import annotations

from urllib.parse import urlparse

from .keywords import DOMAIN_VOCAB


def infer_category_and_format(url: str) -> tuple[str, str]:
    low = (url or "").lower()
    host = urlparse(low).netloc

    if low.endswith(".pdf"):
        return "Document", "PDF"
    if low.endswith((".csv", ".json", ".jsonl", ".parquet", ".xlsx", ".txt")):
        fmt = low.rsplit(".", 1)[-1].upper()
        fmt = {"JSONL": "JSONL", "XLSX": "XLSX"}.get(fmt, fmt)
        return "Dataset", fmt

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


def refine_domain(default_domain: str, title: str, snippet: str) -> str:
    text = f"{title} {snippet}".lower()
    base = _score(text, DOMAIN_VOCAB.get(default_domain, set()))
    best_domain, best_score = default_domain, base
    for domain, vocab in DOMAIN_VOCAB.items():
        if domain == default_domain:
            continue
        s = _score(text, vocab)
        if s > best_score:
            best_domain, best_score = domain, s
    return best_domain
