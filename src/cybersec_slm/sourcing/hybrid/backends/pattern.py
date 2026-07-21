"""
backends/pattern.py – PatternBackend

Generates rows deterministically from URL templates defined in the config's
`url_patterns` list — no network calls. This is the fastest and most
reliable backend for domains where URL patterns are known in advance (e.g.
RBI notification IDs, SEBI order month/year matrix, Indian bank quarterly
disclosure PDFs).

Each PatternSpec in the config can supply either:
  - id_range: [start, end]  →  generates template.format(id=i)
  - items: [{key: val}, …]  →  generates template.format(**item)

Rows are yielded in order across all patterns until `needed` is reached.
"""

from __future__ import annotations

from typing import Any

from .base import Backend, make_row


class PatternBackend(Backend):
    """Generate rows from URL templates without any network call."""

    name = "pattern"

    def fetch(
        self,
        keywords: dict[str, list[str]],
        needed: int,
        seen_urls: set[str],
        config: Any,
    ) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        bc = config.api_backends.get("pattern")
        tags = config.default_tags

        for spec in config.url_patterns:
            if len(rows) >= needed:
                break

            # Determine the iterable of substitution dicts
            if spec.id_range:
                start, end = spec.id_range
                subs = [{"id": i} for i in range(start, end + 1)]
            elif spec.items:
                subs = spec.items
            else:
                continue

            for sub in subs:
                if len(rows) >= needed:
                    break
                try:
                    url = spec.template.format(**sub)
                    desc = spec.description_template.format(**sub)
                except (KeyError, ValueError):
                    continue

                if url in seen_urls:
                    continue
                seen_urls.add(url)

                rows.append(make_row(
                    name=desc[:80],
                    subdomain=spec.subdomain,
                    country=spec.country,
                    description=desc,
                    url=url,
                    field=config.field,
                    category=spec.category,
                    fmt=spec.fmt,
                    license_=bc.license if (bc and bc.license) else spec.license,
                    author=spec.author,
                    tags=tags,
                    note=spec.note,
                ))

        return rows
