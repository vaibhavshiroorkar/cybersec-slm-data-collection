#!/usr/bin/env python3
"""One config per profile for the sourcing engine: ``sourcing.yaml``.

This is the single, generalized description of *how a profile is sourced* — which
backends run and with what limits, the license policy, the row targets, the
country bias, and the quality thresholds. It replaces the three overlapping config
files the old engines each carried (``hybrid_config.yaml`` + ``harvest.yaml``, and
the discovery knobs scattered across ``keywords.yaml`` + env vars).

Separation of concerns:

* ``keywords.yaml`` remains the **taxonomy** (sub-domains, keywords, enum codes,
  vocab, restricted hosts) — it is read by *every* stage, not just sourcing.
* ``sourcing.yaml`` holds only **sourcing settings** — so a profile stays isolated
  and portable: adapt the engine to a new corpus by editing these two files, no
  Python change.

A missing ``sourcing.yaml`` is not an error: :func:`load` returns sensible defaults
derived from the active profile's taxonomy (engines, restricted hosts, keywords),
so a freshly-created profile sources immediately.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# The catalog's ingestion gate keeps only rows whose license is clearly commercial;
# unknown rows survive sourcing but are gated later. "real_or_unknown" is the strict
# default: keep a real (backend-metadata) license or Unknown, never a fabricated one.
LICENSE_POLICIES = ("real_or_unknown", "commercial_only")

# Backends that fetch from an authenticated/structured API and return already-live
# URLs — the engine skips the liveness HTTP check for these (it would only cost
# latency to re-confirm what the API just listed).
API_BACKENDS = frozenset({"huggingface", "github", "arxiv", "ckan", "kaggle", "zenodo"})


@dataclass
class BackendSettings:
    """Per-backend knobs. Unknown keys are preserved in :attr:`extra` for a backend
    that wants a bespoke option without a schema change."""

    enabled: bool = True
    per_keyword_limit: int = 50
    token_env: str = ""          # env var holding an auth token (github, kaggle)
    api_key_env: str = ""        # env var holding an API key (ckan/data.gov.in)
    base_url: str = ""           # override a backend's default base URL (ckan)
    engines: str = ""            # searxng: comma-separated engine list
    url: str = ""                # searxng: instance URL
    last_resort: bool = False    # run this backend only after the others (searxng)
    # Per-request HTTP timeout. Kept short on purpose: an unreachable host costs
    # this much per shot, and a long timeout is what makes a dead backend look
    # like a hung run (data.gov.in times out on every request from some networks).
    timeout: float = 15.0
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class QualitySettings:
    """Cheap relevance gates applied after the junk/restricted/listing drop."""

    # Words whose presence in a candidate's title/description drops it as off-topic.
    off_topic_signals: list[str] = field(default_factory=list)
    # Minimum count of the sub-domain's vocab terms that must appear in the text
    # (0 = off).
    min_keyword_hits: int = 0
    # Which backends the min_keyword_hits floor applies to. It is deliberately NOT
    # applied to the dataset APIs: their results are already bound to the query, and
    # their titles/subtitles are terse — measured on real output, a floor of 1 threw
    # away 5 of 12 genuinely on-topic Kaggle rows (including the Elliptic set, *the*
    # canonical bitcoin AML dataset). The broad scientific/web backends are where
    # off-subject results actually come from (Zenodo answered a "money laundering"
    # query with a beetle-taxonomy record), so the floor is scoped to them.
    # An empty list applies the floor to every backend.
    relevance_backends: list[str] = field(
        default_factory=lambda: ["zenodo", "arxiv", "searxng"])


@dataclass
class SourcingConfig:
    """Complete sourcing description for one profile."""

    profile: str
    keywords: dict[str, list[str]]                # sub-domain -> [keyword, ...]
    output_csv: str                               # the profile's Sources.csv
    restricted_hosts: dict[str, str]              # host -> why (single source of truth)

    target_total: int | None = None               # global cap on rows added (None = uncapped)
    target_per_subdomain: int | None = None        # per-sub-domain valid target
    country_bias: dict[str, float] = field(default_factory=dict)
    country_filter: str | None = None              # keep only this country when set

    license_policy: str = "real_or_unknown"
    enrich_unknown: bool = True                    # run enrich.Enricher on Unknown rows
    allow_owned_first_party: bool = False          # allow the profile's owned-host stamp

    verify_liveness: bool = True                   # HTTP-check non-API URLs before keeping
    workers: int = 12                              # enrichment/verify thread pool size
    # Circuit breaker: a backend that returns nothing this many times in a row is
    # dropped for the rest of the run. Without it an unreachable host (or one
    # missing its credentials) burns one timeout per keyword for the whole run.
    max_consecutive_empty: int = 5

    backends: dict[str, BackendSettings] = field(default_factory=dict)
    quality: QualitySettings = field(default_factory=QualitySettings)

    @property
    def primary_country(self) -> str:
        return max(self.country_bias, key=self.country_bias.get) if self.country_bias else ""

    def enabled_backends(self) -> list[str]:
        """Backend names to run, priority order, last-resort ones last."""
        order = ["ckan", "huggingface", "kaggle", "zenodo", "github", "arxiv", "searxng"]
        active = [b for b in order if b in self.backends and self.backends[b].enabled]
        return sorted(active, key=lambda b: self.backends[b].last_resort)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def _default_backends() -> dict[str, BackendSettings]:
    """The built-in backend roster: real-metadata APIs first, SearXNG last-resort."""
    return {
        "ckan": BackendSettings(enabled=True, per_keyword_limit=100,
                                base_url="https://www.data.gov.in",
                                api_key_env="DATAGOVINDIA_API_KEY"),
        "huggingface": BackendSettings(enabled=True, per_keyword_limit=100),
        # token_env is informational for kaggle: the backend authenticates through
        # the official kaggle SDK, which reads KAGGLE_USERNAME + KAGGLE_KEY (or
        # ~/.kaggle/kaggle.json) itself rather than via this field.
        "kaggle": BackendSettings(enabled=True, per_keyword_limit=50,
                                  token_env="KAGGLE_KEY"),
        "zenodo": BackendSettings(enabled=True, per_keyword_limit=50),
        "github": BackendSettings(enabled=True, per_keyword_limit=80,
                                  token_env="GITHUB_TOKEN"),
        "arxiv": BackendSettings(enabled=True, per_keyword_limit=50),
        "searxng": BackendSettings(enabled=True, per_keyword_limit=25,
                                   url="http://localhost:8080", last_resort=True),
    }


def _parse_backend(d: dict[str, Any]) -> BackendSettings:
    known = {"enabled", "per_keyword_limit", "token_env", "api_key_env",
             "base_url", "engines", "url", "last_resort", "timeout"}
    return BackendSettings(
        enabled=d.get("enabled", True),
        per_keyword_limit=int(d.get("per_keyword_limit", 50)),
        token_env=d.get("token_env", ""),
        api_key_env=d.get("api_key_env", ""),
        base_url=d.get("base_url", ""),
        engines=d.get("engines", ""),
        url=d.get("url", ""),
        last_resort=bool(d.get("last_resort", False)),
        timeout=float(d.get("timeout", 15.0)),
        extra={k: v for k, v in d.items() if k not in known},
    )


def _resolve_paths(profile: str | None) -> tuple[str, str]:
    """Return ``(profile_name, sourcing_yaml_path)`` for ``profile`` (or the active)."""
    from . import profiles
    name = profile or profiles.active()
    path = str(Path(profiles.profile_dir(name)) / "sourcing.yaml")
    return name, path


def default_config(profile: str | None = None) -> SourcingConfig:
    """Config for ``profile`` derived entirely from its taxonomy (no YAML on disk)."""
    from . import catalog
    from . import keywords as kw
    from . import profiles

    name = profile or profiles.active()
    cat = catalog.load(profile=name)
    kws = {sub: list(spec.get("keywords", [])) for sub, spec in cat.items()}
    # SearXNG defaults to the profile's reliable API engines.
    backends = _default_backends()
    backends["searxng"].engines = kw.default_engines()
    return SourcingConfig(
        profile=name,
        keywords=kws,
        output_csv=profiles.catalog_path(name),
        restricted_hosts=dict(kw.RESTRICTED_HOSTS),
        backends=backends,
    )


def load(profile: str | None = None) -> SourcingConfig:
    """Load ``profile``'s ``sourcing.yaml``, falling back to taxonomy defaults.

    Any key omitted from the YAML keeps its default, so a partial file (e.g. only
    ``target``) is valid. Keywords and restricted hosts always come from the live
    taxonomy unless the YAML explicitly overrides them, so the two files never drift.
    """
    name, path = _resolve_paths(profile)
    cfg = default_config(name)

    p = Path(path)
    if not p.exists():
        return cfg
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}

    tgt = raw.get("target", {}) or {}
    cfg.target_total = tgt.get("total", cfg.target_total)
    cfg.target_per_subdomain = tgt.get("per_subdomain", cfg.target_per_subdomain)

    country = raw.get("country", {}) or {}
    cfg.country_bias = country.get("bias", cfg.country_bias)
    cfg.country_filter = country.get("filter", cfg.country_filter)

    lic = raw.get("license", {}) or {}
    cfg.license_policy = lic.get("policy", cfg.license_policy)
    cfg.enrich_unknown = lic.get("enrich_unknown", cfg.enrich_unknown)
    cfg.allow_owned_first_party = lic.get("allow_owned_first_party",
                                          cfg.allow_owned_first_party)

    if "restricted_hosts" in raw and raw["restricted_hosts"] is not None:
        rh = raw["restricted_hosts"]
        # Accept either a list (reasons default) or a {host: reason} mapping; merge
        # onto the taxonomy's so the YAML extends rather than silently replaces it.
        if isinstance(rh, dict):
            cfg.restricted_hosts = {**cfg.restricted_hosts, **rh}
        else:
            cfg.restricted_hosts = {**cfg.restricted_hosts,
                                    **{h: "restricted by sourcing.yaml" for h in rh}}

    if "keywords" in raw and raw["keywords"]:
        cfg.keywords = raw["keywords"]

    cfg.verify_liveness = raw.get("verify_liveness", cfg.verify_liveness)
    cfg.workers = int(raw.get("workers", cfg.workers))
    cfg.max_consecutive_empty = int(raw.get("max_consecutive_empty",
                                            cfg.max_consecutive_empty))

    if "backends" in raw and raw["backends"] is not None:
        for bname, bd in (raw["backends"] or {}).items():
            cfg.backends[bname] = _parse_backend(bd or {})

    q = raw.get("quality", {}) or {}
    default_q = QualitySettings()
    cfg.quality = QualitySettings(
        off_topic_signals=[s.lower() for s in q.get("off_topic_signals", [])],
        min_keyword_hits=int(q.get("min_keyword_hits", 0)),
        relevance_backends=[str(b).lower() for b in
                            q.get("relevance_backends", default_q.relevance_backends)],
    )
    return cfg
