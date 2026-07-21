#!/usr/bin/env python3
"""Backend contract for the sourcing engine: a :class:`Candidate` + :class:`Backend`.

Every backend answers one ``search(subdomain, keyword, limit, cfg)`` call with a
list of :class:`Candidate` records. A Candidate wraps the shared
:class:`~cybersec_slm.sourcing.search.Result` (title/link/snippet — what the row
builder consumes) plus **only metadata the backend actually got from its source**:
license, author, popularity, tags, size, dates. The one rule every backend obeys:

    A backend NEVER invents a license. ``Candidate.license`` is set only from the
    source's real metadata (HuggingFace card, GitHub license API, arXiv/Zenodo
    license field, CKAN package license). When the source exposes none, it is left
    empty ("") and the engine's enrich-on-unknown step may fill it — but nothing is
    fabricated. This is the defect the old ``pattern`` backend embodied (stamping
    ``First-party (owner-authorized)`` on guessed URLs) and is designed out here.

The engine (:mod:`cybersec_slm.sourcing.orchestrator`) is what gates, dedups,
enriches, and appends; backends are pure fetchers and stay unit-testable.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..search import Result

if TYPE_CHECKING:
    from ..config import SourcingConfig


@dataclass
class Candidate:
    """One backend hit: a search :class:`Result` plus real, backend-sourced metadata.

    ``license`` is the source's *actual* license string (SPDX id or free text) or
    ``""`` when the source exposes none — never a guess. Blank metadata fields are
    left blank so the row builder / enricher fill them rather than being overwritten
    with fabricated values.
    """

    subdomain: str
    result: Result
    backend: str = ""
    license: str = ""            # real metadata only; "" means "unknown, let enrich try"
    author: str = ""
    popularity: str = ""
    tags: str = ""
    last_updated: str = ""
    size_mb: str = ""
    file_count: str = ""
    category: str = ""           # overrides the link-inferred Category when set
    fmt: str = ""                # overrides the link-inferred Original Format when set
    country: str = ""            # overrides the link-inferred Country when set
    note: str = ""

    def metadata_row(self) -> dict[str, str]:
        """The catalog columns this Candidate carries real values for (blanks omitted).

        The engine overlays these onto the row built from ``result`` *without*
        clobbering anything the builder already set, so a backend's genuine license
        wins over a blank but never invents one.
        """
        pairs = {
            "License": self.license,
            "Author": self.author,
            "Popularity": self.popularity,
            "Tags": self.tags,
            "Last Updated": self.last_updated,
            "Original Size (MB)": self.size_mb,
            "File Count": self.file_count,
            "Category": self.category,
            "Original Format": self.fmt,
            "Country": self.country,
            "Note": self.note,
        }
        return {k: v for k, v in pairs.items() if str(v).strip()}


class Backend(ABC):
    """A sourcing backend. Subclasses set :attr:`name` and implement :meth:`search`."""

    name: str = "base"

    def available(self, cfg: "SourcingConfig") -> bool:
        """Whether this backend is enabled for ``cfg`` (default: its enabled flag)."""
        bc = cfg.backends.get(self.name)
        return bool(bc and bc.enabled)

    @abstractmethod
    def search(self, subdomain: str, keyword: str, limit: int,
               cfg: "SourcingConfig") -> list[Candidate]:
        """Return up to ``limit`` candidates for ``keyword`` under ``subdomain``.

        Best-effort: a network/parse failure returns ``[]`` (the engine logs and
        moves on); it must never raise for an ordinary empty/failed query.
        """
        ...

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<Backend:{self.name}>"
