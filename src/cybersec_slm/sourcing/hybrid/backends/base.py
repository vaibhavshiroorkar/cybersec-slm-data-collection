"""
backends/base.py – Abstract base class for all hybrid sourcing backends.

Every backend implements fetch() and returns a list of row dicts that conform
to the Sources.csv schema. The coordinator calls fetch() and applies quality
filtering before adding rows to the catalog.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import date
from typing import Any

TODAY = date.today().strftime("%d/%m/%Y")

# The canonical Sources.csv field names
CSV_FIELDS = [
    "Name", "Sub-Domain", "Field", "Country", "Description",
    "Dataset Link", "File Count", "Category", "Original Format",
    "Original Size (MB)", "JSONL Size (MB)", "Total Lines",
    "Cleaned Size (MB)", "Cleaned Lines", "License", "Last Updated",
    "Uploaded?", "Cleaned?", "Verified?", "Is Synthetic?",
    "Date Added", "Author", "Popularity", "Tags", "Note",
]


def make_row(
    name: str,
    subdomain: str,
    country: str,
    description: str,
    url: str,
    *,
    field: str = "Finance",
    category: str = "Document",
    fmt: str = "HTML",
    license_: str = "First-party (owner-authorized)",
    author: str = "",
    tags: str = "",
    note: str = "",
) -> dict[str, str]:
    """Build a Sources.csv-compatible row dict."""
    return {
        "Name": str(name)[:80],
        "Sub-Domain": subdomain,
        "Field": field,
        "Country": country,
        "Description": str(description)[:300],
        "Dataset Link": url,
        "File Count": "",
        "Category": category,
        "Original Format": fmt,
        "Original Size (MB)": "",
        "JSONL Size (MB)": "",
        "Total Lines": "",
        "Cleaned Size (MB)": "",
        "Cleaned Lines": "",
        "License": license_,
        "Last Updated": "",
        "Uploaded?": "",
        "Cleaned?": "",
        "Verified?": "",
        "Is Synthetic?": "",
        "Date Added": TODAY,
        "Author": author,
        "Popularity": "",
        "Tags": tags,
        "Note": note,
    }


class Backend(ABC):
    """
    Abstract backend.  Subclasses override `name` and implement `fetch()`.

    fetch() is called by the coordinator with:
      - keywords   : {subdomain: [kw, ...]} from the config
      - needed     : how many rows are still required (upper bound to generate)
      - seen_urls  : set[str] of URLs already in the catalog (dedup)
      - config     : the full HybridConfig

    It should return a list of row dicts, stopping once len(rows) >= needed.
    Quality filtering (scorer.passes_quality) is applied by the coordinator
    after fetch(), but backends should apply cheap self-filtering to avoid
    producing obvious junk.
    """

    name: str = "base"

    @abstractmethod
    def fetch(
        self,
        keywords: dict[str, list[str]],
        needed: int,
        seen_urls: set[str],
        config: Any,          # HybridConfig — typed as Any to avoid circular
    ) -> list[dict[str, str]]:
        ...

    def __repr__(self) -> str:
        return f"<Backend:{self.name}>"
