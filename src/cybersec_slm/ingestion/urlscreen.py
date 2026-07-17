#!/usr/bin/env python3
"""Decide whether ingestion is allowed to fetch a URL.

The catalog is filled by automated discovery (SearXNG search results), not by a
human approving each row, so "it is in Sources.csv" is not evidence that a URL is
safe to request. This module is what stands between a discovered URL and an
internal service: it refuses non-HTTP schemes, embedded credentials, and any host
that resolves to a private, loopback, link-local or cloud-metadata address.

This is the control the removed allowlist gate used to gesture at. The allowlist
was dropped deliberately (commit ``3aa6f20``: "suitability is decided by code,
not a hand-maintained approve list") and that reasoning stands — so the
replacement is a rule, not a list: it needs no maintenance and cannot go stale.

Screening the *resolved address* rather than the spelling of the host is the
point. ``http://internal.corp/`` and ``http://10.0.0.5/`` are the same request;
only the second is obvious.

Two entry points, because callers want different things:
    :func:`screen` -- a reason string ("" when allowed), for reporting.
    :func:`check`  -- raises :class:`BlockedURL`, for a fetch path that must stop.

Pure apart from DNS, and DNS goes through :func:`_resolve` so tests can fake it.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

# The schemes a corpus fetch can legitimately use. Everything else (file://,
# ftp://, gopher://, data:) either reads the local disk or reaches a protocol
# with no business in this pipeline.
ALLOWED_SCHEMES = frozenset({"http", "https"})


class BlockedURL(RuntimeError):
    """Raised by :func:`check` when a URL must not be fetched."""


def _resolve(host: str) -> list[str]:
    """Every address ``host`` resolves to. Indirected so tests can fake DNS.

    All of them matter, not just the first: a host with one public and one
    private address must be refused, and which one comes back can vary per call.
    """
    infos = socket.getaddrinfo(host, None)
    return [i[4][0] for i in infos]


def _address_reason(addr: str) -> str:
    """Why ``addr`` must not be fetched, or "" when it is a public address."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return f"could not parse the resolved address {addr!r}"
    if ip.is_link_local:
        # 169.254.169.254 is the cloud metadata endpoint: it hands out instance
        # credentials to anything that can make an HTTP request from the host.
        return (f"{addr} is link-local (the cloud metadata endpoint lives here); "
                "refusing to fetch it")
    if ip.is_loopback:
        return f"{addr} is loopback; refusing to fetch a service on this machine"
    if ip.is_private:
        return f"{addr} is a private address; refusing to fetch an internal service"
    if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return f"{addr} is a reserved/multicast/unspecified address"
    return ""


def screen(url: str) -> str:
    """Why ``url`` must not be fetched, or "" when it is allowed.

    Fails closed: anything unparseable, unresolvable or unexpected is refused
    rather than waved through, because the cost of a wrong "allow" here is an
    internal service being fetched into a public corpus, and the cost of a wrong
    "refuse" is one source not being ingested.
    """
    raw = (url or "").strip()
    if not raw:
        return "empty URL"
    try:
        parts = urlsplit(raw)
    except ValueError as e:
        return f"unparseable URL ({e})"

    scheme = (parts.scheme or "").lower()
    if not scheme:
        return f"no scheme in {raw!r}; only {sorted(ALLOWED_SCHEMES)} are fetched"
    if scheme not in ALLOWED_SCHEMES:
        return f"scheme {scheme!r} is not fetched; only {sorted(ALLOWED_SCHEMES)}"
    if parts.username or parts.password:
        return "credentials embedded in the URL; refusing to fetch it"

    try:
        host = parts.hostname
    except ValueError as e:
        return f"unparseable host ({e})"
    if not host:
        return f"no host in {raw!r}"

    # A literal IP needs no DNS; a name does. Screen whatever comes back either way.
    try:
        addrs = _resolve(host)
    except OSError as e:
        return f"could not resolve {host!r} ({e}); refusing to fetch it"
    if not addrs:
        return f"{host!r} resolved to no address"

    for addr in addrs:
        reason = _address_reason(addr)
        if reason:
            return f"{host!r} -> {reason}"
    return ""


def check(url: str) -> None:
    """Raise :class:`BlockedURL` when ``url`` must not be fetched."""
    reason = screen(url)
    if reason:
        raise BlockedURL(reason)
