"""
config.py – HybridConfig dataclass + YAML loader.

A HybridConfig fully describes a sourcing situation:
  - what domain/field we are collecting for
  - how many rows to target
  - what keywords to search per subdomain
  - what URL patterns to generate (e.g. RBI notification IDs)
  - which API backends to enable and with what limits
  - quality rules to reject off-topic rows

Writing a new YAML config is all that is needed to adapt this engine
to a completely new domain — no Python code changes required.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Sub-configs
# ---------------------------------------------------------------------------

@dataclass
class PatternSpec:
    """A URL template that generates candidate rows without any network call."""
    template: str                       # e.g. "https://example.com/id={id}"
    subdomain: str
    country: str = "India"
    license: str = "First-party (owner-authorized)"
    description_template: str = "Source {id}"
    category: str = "Document"
    fmt: str = "HTML"
    author: str = ""
    note: str = ""
    # Numeric ID range: generates template.format(id=i) for i in range(start, end+1)
    id_range: tuple[int, int] | None = None
    # Static list of substitution dicts: generates template.format(**d) for d in items
    items: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class BackendConfig:
    enabled: bool = True
    per_keyword_limit: int = 100
    # API-specific
    token_env: str = ""           # env var name holding auth token
    base_url: str = ""            # override default base URL
    api_key_env: str = ""         # for CKAN
    engines: str = ""             # for SearXNG: comma-separated engine list
    searxng_url: str = ""         # SearXNG instance URL
    max_pages: int = 5            # SearXNG pagination depth
    country: str = ""             # force Country label for all rows from this backend
    license: str = ""             # force License for all rows from this backend
    # Country-signal keywords: if any appear in name/desc → mark as primary country
    country_signal_keywords: list[str] = field(default_factory=list)


@dataclass
class QualityConfig:
    min_relevance_score: float = 0.25
    reject_off_topic_hosts: bool = True
    reject_listing_pages: bool = True
    off_topic_signals: list[str] = field(default_factory=list)
    domain_signals: list[str] = field(default_factory=list)
    # Hosts always blocked (licensing or off-topic)
    blocked_hosts: list[str] = field(default_factory=list)
    # Hosts always trusted (skip relevance check)
    trusted_hosts: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Main config
# ---------------------------------------------------------------------------

@dataclass
class HybridConfig:
    """Complete description of one sourcing situation."""
    name: str
    field: str                              # e.g. "Finance"
    target: int                             # total rows to produce
    subdomains: list[str]
    country_bias: dict[str, float]          # {"India": 0.65, "Global": 0.35}
    keywords: dict[str, list[str]]          # subdomain → [keyword, ...]
    output_csv: str                         # path to Sources.csv

    url_patterns: list[PatternSpec] = field(default_factory=list)
    api_backends: dict[str, BackendConfig] = field(default_factory=dict)
    quality: QualityConfig = field(default_factory=QualityConfig)

    # Optional: seed rows injected verbatim before any backend runs
    seed_rows: list[dict[str, str]] = field(default_factory=list)

    # Tags added to every row
    default_tags: str = ""

    @property
    def primary_country(self) -> str:
        """The country with the highest bias weight."""
        return max(self.country_bias, key=self.country_bias.get)

    @property
    def backend_order(self) -> list[str]:
        """Backends ordered by reliability/quality (best first)."""
        _ORDER = ["pattern", "ckan", "huggingface", "github", "arxiv", "searxng"]
        return [b for b in _ORDER if b in self.api_backends
                and self.api_backends[b].enabled]

    def choose_backends(self, gap: int) -> list[str]:
        """Strategy selector: pick backends appropriate for the remaining gap."""
        all_backends = self.backend_order
        if gap <= 0:
            return []
        if gap > 5000:
            return all_backends                # use everything
        if gap > 1000:
            return [b for b in all_backends if b != "pattern"]
        if gap > 200:
            return [b for b in all_backends if b not in ("pattern", "ckan")]
        # Fine-grained discovery for last few rows
        return [b for b in all_backends if b in ("searxng", "arxiv")]


# ---------------------------------------------------------------------------
# YAML loader
# ---------------------------------------------------------------------------

def _parse_pattern_spec(d: dict) -> PatternSpec:
    id_range = d.get("id_range")
    return PatternSpec(
        template=d["template"],
        subdomain=d.get("subdomain", ""),
        country=d.get("country", "India"),
        license=d.get("license", "First-party (owner-authorized)"),
        description_template=d.get("description_template", "Source {id}"),
        category=d.get("category", "Document"),
        fmt=d.get("fmt", d.get("format", "HTML")),
        author=d.get("author", ""),
        note=d.get("note", ""),
        id_range=tuple(id_range) if id_range else None,
        items=d.get("items", []),
    )


def _parse_backend_config(d: dict) -> BackendConfig:
    return BackendConfig(
        enabled=d.get("enabled", True),
        per_keyword_limit=d.get("per_keyword_limit", 100),
        token_env=d.get("token_env", ""),
        base_url=d.get("base_url", ""),
        api_key_env=d.get("api_key_env", ""),
        engines=d.get("engines", ""),
        searxng_url=d.get("url", d.get("searxng_url", "")),
        max_pages=d.get("max_pages", 5),
        country=d.get("country", ""),
        license=d.get("license", ""),
        country_signal_keywords=d.get("country_signal_keywords", []),
    )


def _parse_quality(d: dict) -> QualityConfig:
    return QualityConfig(
        min_relevance_score=d.get("min_relevance_score", 0.25),
        reject_off_topic_hosts=d.get("reject_off_topic_hosts", True),
        reject_listing_pages=d.get("reject_listing_pages", True),
        off_topic_signals=[s.lower() for s in d.get("off_topic_signals", [])],
        domain_signals=[s.lower() for s in d.get("domain_signals", [])],
        blocked_hosts=d.get("blocked_hosts", []),
        trusted_hosts=d.get("trusted_hosts", []),
    )


def load_config(path: str | Path) -> HybridConfig:
    """Load a YAML hybrid config file into a HybridConfig instance."""
    path = Path(path)
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    profile = raw.get("profile", {})
    return HybridConfig(
        name=profile.get("name", path.stem),
        field=profile.get("field", "Finance"),
        target=int(profile.get("target", 10000)),
        subdomains=raw.get("subdomains", []),
        country_bias=profile.get("country_bias", {"Global": 1.0}),
        keywords=raw.get("keywords", {}),
        output_csv=profile.get("output_csv", "sources/profiles/ubi/Sources.csv"),
        url_patterns=[_parse_pattern_spec(p) for p in raw.get("url_patterns", [])],
        api_backends={k: _parse_backend_config(v)
                      for k, v in raw.get("api_backends", {}).items()},
        quality=_parse_quality(raw.get("quality", {})),
        seed_rows=raw.get("seed_rows", []),
        default_tags=profile.get("default_tags", ""),
    )
