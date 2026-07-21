"""backends/__init__.py – Exports all backend classes."""

from .arxiv import ArXivBackend
from .base import Backend, make_row
from .ckan import CKANBackend
from .github import GitHubBackend
from .huggingface import HuggingFaceBackend
from .pattern import PatternBackend
from .searxng import SearXNGBackend

BACKEND_REGISTRY: dict[str, type[Backend]] = {
    "pattern": PatternBackend,
    "huggingface": HuggingFaceBackend,
    "github": GitHubBackend,
    "arxiv": ArXivBackend,
    "ckan": CKANBackend,
    "searxng": SearXNGBackend,
}

__all__ = [
    "Backend", "make_row",
    "PatternBackend", "HuggingFaceBackend", "GitHubBackend",
    "ArXivBackend", "CKANBackend", "SearXNGBackend",
    "BACKEND_REGISTRY",
]
