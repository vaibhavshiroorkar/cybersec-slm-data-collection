"""
cybersec_slm.sourcing.hybrid
============================
Generalized hybrid sourcing engine.

Combines multiple backends (URL pattern generation, direct APIs, SearXNG,
CKAN) into a single config-driven pipeline that adapts to any domain.

Usage:
    uv run cybersec-slm hybrid-source --config path/to/hybrid_config.yaml

The YAML config describes the domain, keywords, country bias, quality
rules, and which backends to enable — no code changes needed for new domains.
"""

from .config import HybridConfig, load_config
from .coordinator import HybridSourcer

__all__ = ["HybridConfig", "HybridSourcer", "load_config"]
