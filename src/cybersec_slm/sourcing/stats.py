#!/usr/bin/env python3
"""Discovery funnel tally: what a sourcing run pulled back, and what it kept.

A sourcing run turns a lot of search hits into a few catalog rows, and until now
the losses were invisible — :func:`quality.passes` returned False and the result
vanished. That hides the two things worth knowing:

  * **Is the keyword set aimed correctly?** A domain whose hits are 80% listing
    pages needs different keywords, not a longer run.
  * **What is the legal scope actually costing?** For the ``ubi`` profile, the
    ``restricted host`` bucket is the concrete answer to "how much regulator
    content did we have to turn away", broken down per host.

:class:`Funnel` is a plain counter with no I/O, so the discovery loop can call it
on the hot path and it stays unit-testable. :meth:`Funnel.as_dict` is what lands
in the run's ``summary-*.json``, and the dashboard reads it back from there.

The stages tally as a strict funnel — every hit lands in exactly one terminal
bucket::

    found                       search results fetched into the buffer
      ├─ dropped[category]      quality filter (junk / restricted / listing / bad)
      ├─ duplicates             already in the catalog, or seen earlier this run
      ├─ candidates             survived to enrichment
      │    ├─ license[blocked]  a confirmed-red license  -> never appended
      │    ├─ license[unknown]  license could not be resolved
      │    └─ license[ok]       clearly commercial
      └─ unprocessed            fetched, but the run stopped before reaching them

``unprocessed`` is not a loss — it is the tail of the buffer left over when a run
ends on its ``--max-total`` cap or time budget with results still in hand. It is
reported rather than elided because ``found`` is incremented when a result is
*fetched*, not when it is *examined*: without this bucket the other three would
silently fail to sum to ``found``, and a funnel whose arithmetic does not close
is worse than no funnel at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .quality import DROP_CATEGORIES

# License verdicts, in the order the dashboard lists them. Mirrors
# ``ingestion.license_gate.license_verdict``'s three states.
LICENSE_VERDICTS: tuple[str, ...] = ("ok", "unknown", "blocked")


@dataclass
class Funnel:
    """Counts for one sourcing run. Mutated on the hot path; no I/O."""

    found: int = 0
    duplicates: int = 0
    candidates: int = 0
    appended: int = 0

    # category -> count, over quality.DROP_CATEGORIES
    dropped: dict[str, int] = field(default_factory=dict)
    # host -> count, for the restricted-host bucket only (the legal-scope view)
    restricted_by_host: dict[str, int] = field(default_factory=dict)
    # verdict -> count, over LICENSE_VERDICTS, for candidates that reached the gate
    license: dict[str, int] = field(default_factory=dict)
    # sub-domain -> {"found", "dropped", "candidates"} — per-domain aim
    by_domain: dict[str, dict[str, int]] = field(default_factory=dict)

    def _domain(self, domain: str) -> dict[str, int]:
        return self.by_domain.setdefault(
            domain, {"found": 0, "dropped": 0, "candidates": 0})

    def hit(self, domain: str) -> None:
        """One search result came back for ``domain``."""
        self.found += 1
        self._domain(domain)["found"] += 1

    def drop(self, domain: str, category: str, host: str = "") -> None:
        """A result was dropped by the quality filter for ``category``."""
        self.dropped[category] = self.dropped.get(category, 0) + 1
        self._domain(domain)["dropped"] += 1
        if category == "restricted host" and host:
            self.restricted_by_host[host] = self.restricted_by_host.get(host, 0) + 1

    def duplicate(self, domain: str) -> None:
        """A result was already in the catalog, or already seen this run."""
        self.duplicates += 1
        self._domain(domain)

    def candidate(self, domain: str) -> None:
        """A result survived the filters and became a catalog candidate."""
        self.candidates += 1
        self._domain(domain)["candidates"] += 1

    def verdict(self, verdict: str) -> None:
        """Record a candidate's resolved license verdict (ok/unknown/blocked)."""
        self.license[verdict] = self.license.get(verdict, 0) + 1

    @property
    def unprocessed(self) -> int:
        """Hits fetched but never examined — the buffer tail when a run stops early.

        Derived, not counted: it is whatever ``found`` has left over once the three
        terminal buckets are subtracted, which is exactly the set of results the
        run had in hand when its cap or time budget ended it. Clamped at 0 so a
        counting bug can never surface as a negative.
        """
        seen = sum(self.dropped.values()) + self.duplicates + self.candidates
        return max(self.found - seen, 0)

    def as_dict(self) -> dict:
        """The JSON shape written to ``summary-*.json`` (zeros are kept explicit).

        Every :data:`~.quality.DROP_CATEGORIES` and :data:`LICENSE_VERDICTS` key is
        present even at zero, so the dashboard renders a stable table rather than
        one whose rows appear and disappear between runs.
        """
        return {
            "found": self.found,
            "dropped": {c: self.dropped.get(c, 0) for c in DROP_CATEGORIES},
            "dropped_total": sum(self.dropped.values()),
            "duplicates": self.duplicates,
            "candidates": self.candidates,
            "unprocessed": self.unprocessed,
            "license": {v: self.license.get(v, 0) for v in LICENSE_VERDICTS},
            "appended": self.appended,
            "restricted_by_host": dict(
                sorted(self.restricted_by_host.items(),
                       key=lambda kv: (-kv[1], kv[0]))),
            "by_domain": self.by_domain,
        }
