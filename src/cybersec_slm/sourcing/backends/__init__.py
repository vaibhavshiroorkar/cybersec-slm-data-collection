#!/usr/bin/env python3
"""Sourcing backends: pluggable, real-metadata source discoverers.

Each backend answers ``search(subdomain, keyword, limit, cfg)`` with a list of
:class:`~cybersec_slm.sourcing.backends.base.Candidate` records carrying only the
license the source actually declares. The engine
(:mod:`cybersec_slm.sourcing.orchestrator`) gates, dedups, enriches, and appends.

Add a backend by implementing :class:`~.base.Backend` and registering it here.
"""

from __future__ import annotations

from .arxiv import ArXivBackend
from .base import Backend, Candidate
from .ckan import CKANBackend
from .github import GitHubBackend
from .huggingface import HuggingFaceBackend
from .kaggle import KaggleBackend
from .searxng import SearXNGBackend
from .zenodo import ZenodoBackend

# name -> Backend class. The engine instantiates and runs enabled ones in the
# priority order from SourcingConfig.enabled_backends().
BACKEND_REGISTRY: dict[str, type[Backend]] = {
    "huggingface": HuggingFaceBackend,
    "github": GitHubBackend,
    "arxiv": ArXivBackend,
    "ckan": CKANBackend,
    "kaggle": KaggleBackend,
    "zenodo": ZenodoBackend,
    "searxng": SearXNGBackend,
}


def get_backend(name: str) -> Backend | None:
    """Instantiate the backend named ``name``, or ``None`` when unknown."""
    cls = BACKEND_REGISTRY.get(name)
    return cls() if cls else None


__all__ = ["Backend", "Candidate", "BACKEND_REGISTRY", "get_backend"]
