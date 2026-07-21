"""
backends/pattern.py – PatternBackend

Generates rows deterministically from URL templates defined in the config's
`url_patterns` list (e.g. RBI notification IDs, SEBI order month/year matrix,
Indian bank quarterly disclosure PDFs).

Generation itself is still a pure string-format operation with no network
call. But an id_range/items pattern is a *guess* — nothing about the template
guarantees every generated ID actually exists or resolves to a real page. The
old version accepted every generated URL unconditionally; against a host that
the quality scorer trusts (rbi.org.in, sebi.gov.in, ...) that guess sailed
straight into the catalog with zero verification, because host trust alone
was enough to clear the relevance gate downstream. In production this showed
up as ~44% of one catalog being unverified guessed RBI URLs.

Set `verify: true` on the pattern backend config to HTTP-check each candidate
(HEAD, falling back to a ranged GET for hosts that reject HEAD) concurrently
before it's accepted — non-2xx/3xx responses are dropped. This is opt-in
because it adds network calls and turns a previously instant backend into one
bounded by the target host's latency; it is strongly recommended for any
id_range/items pattern that isn't a confirmed listing.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .base import Backend, make_row


def _url_is_live(url: str, timeout: float) -> bool:
    """Best-effort liveness check: HEAD first, GET fallback for hosts that
    reject HEAD (405) or return a generic 200 for HEAD but 404 for GET on some
    misconfigured servers. Any exception (timeout, DNS, connection refused)
    counts as dead — we'd rather under-fill than hand ingestion a dead link."""
    import httpx

    try:
        resp = httpx.head(url, timeout=timeout, follow_redirects=True)
        if resp.status_code == 405:  # method not allowed — some gov servers
            resp = httpx.get(url, timeout=timeout, follow_redirects=True)
        return resp.status_code < 400
    except Exception:
        return False


def _verify_rows(rows: list[dict[str, str]], workers: int,
                 timeout: float) -> list[dict[str, str]]:
    """Concurrently verify a batch of candidate rows; return only the live ones,
    in their original relative order."""
    if not rows:
        return rows

    live: dict[int, dict[str, str]] = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        future_to_idx = {
            pool.submit(_url_is_live, row["Dataset Link"], timeout): i
            for i, row in enumerate(rows)
        }
        for fut in as_completed(future_to_idx):
            idx = future_to_idx[fut]
            try:
                if fut.result():
                    live[idx] = rows[idx]
            except Exception:
                continue

    return [live[i] for i in sorted(live)]


class PatternBackend(Backend):
    """Generate rows from URL templates, optionally verifying liveness."""

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

        if bc and bc.verify and rows:
            before = len(rows)
            rows = _verify_rows(rows, bc.verify_workers, bc.verify_timeout)
            dead = before - len(rows)
            if dead:
                # Verification drops rows outright rather than routing them
                # through the normal reject-reason counter, since this backend
                # has no reference to the coordinator's stats. The coordinator
                # log line will simply show fewer candidates than "needed".
                import sys
                print(f"  [pattern] verify: {dead}/{before} generated URLs "
                      f"were dead (404/timeout/refused) — dropped", file=sys.stderr)

        return rows