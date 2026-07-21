#!/usr/bin/env python3
"""Commercial-only license gate for ingestion.

A source is fetched only if its license clearly permits *unencumbered commercial
use*. This is the ingestion gate: it answers "are we legally allowed to train
commercially on this source?" before anything is downloaded.

The catalog's ``License`` column is free text and wildly inconsistent (SPDX ids,
plain English, named-entity terms, blanks), so classification is keyword-based
over the lowercased, whitespace-collapsed string, and **default-deny**: anything
not recognised as clearly-commercial is blocked until a human either fixes the
license text or extends the allow set. Copyleft / share-alike / non-commercial
licenses are blocked deliberately — they permit commercial use only under
obligations (release derivatives under the same terms) we don't want to inherit.

The check order matters: deny patterns are tested *before* allow patterns, so a
compound string like ``"CC BY-NC-SA 4.0"`` (which also contains an allow
substring) is correctly blocked.

Enforcement is on by default; ``CYBERSEC_SLM_ENFORCE_LICENSE_GATE=0`` disables it
for local dev/testing.

A blank or unrecognized catalog license is not the end of the question: sourcing
admits license-unsure sources on purpose, and this gate resolves them by fetching
the source and reading its stated terms (:func:`deep_license`, backed by
:mod:`cybersec_slm.sourcing.license_detect`). That is what lets a restricted *site*
still contribute its usable *pages* — an all-rights-reserved portal whose RSS feed
reduces to a metadata index — instead of being written off host-wide at sourcing
time. A source whose terms remain unreadable stays denied.

Public API:
    classify_license(raw)   -> (commercial_ok, reason)   # pure classifier
    license_verdict(raw)    -> "ok" | "blocked" | "unknown"  # 3-state
    deep_license(url)       -> canonical license string  # fetches the source
    is_license_ok(descriptor) -> (allowed, reason)       # + deep check + kill switch
"""

from __future__ import annotations

import os
import re
from typing import Literal

from ..core import logger

# Non-commercial, copyleft, share-alike, proprietary, or unresolved-restrictive.
# `lgpl`/`agpl` are listed explicitly because a `\bgpl\b` boundary would not match
# inside them. `nc`/`sa` are matched as whole tokens so they catch `-nc-`/`-sa`
# (and space-separated forms) without firing inside ordinary words (e.g. "usa").
_DENY = re.compile(
    r"\b("
    r"non[- ]?commercial|noncommercial|nc|sa|share[- ]?alike|"
    r"gpl|lgpl|agpl|copyleft|proprietary|all rights reserved|"
    r"no licen[sc]e|need permission|not for commercial|commercial use prohibited"
    r")\b"
)

# Clearly-commercial: permissive OSS, public-domain / government works, bare
# CC0 / CC-BY-4.0 (the deny pass above has already removed -nc/-sa variants), the
# named-entity terms present in this catalog that are free-to-use commercially
# (MITRE ATT&CK/CAPEC/CWE, IETF Trust), and the plain-English usage grants the
# deep detector now records from a source's terms-of-use prose ("free for
# commercial use", "commercial use permitted", "royalty-free", "free to use").
# The deny pass above already turned away the non-commercial forms of these, so a
# grant reaching here is an unencumbered one. `mit` is boundary-matched so it does
# not fire inside "permit"/"limited".
_ALLOW = re.compile(
    r"\b("
    r"mit|apache|bsd|cc0|cdla[- ]permissive|"
    r"public domain|us[- ]gov|u\.s\. gov|government work|"
    r"mitre|ietf|cc[- ]by[- ]?4\.0|open access|"
    r"free for commercial|commercial use permitted|commercial use allowed|"
    r"royalty[- ]free|free to use|free of charge|free for any|free for all|"
    # First-party content: we own it, or hold the owner's authorization for it.
    # Stamped by enrichment for a profile's ``owned_hosts`` (see
    # sourcing.taxonomies.OWNED_LICENSE) and never scraped off a page, so a
    # third-party source cannot talk its way past the gate by printing these words
    # — the host has to be on the profile's owned list for the stamp to be applied.
    r"first[- ]party|owner[- ]authori[sz]ed|"
    # A metadata-only index (title/date/URL). Facts, not copyrightable, so it is
    # the one usable form of an All-Rights-Reserved source's feed. The label is
    # never scraped: rss.scrape_rss stamps it only when it has actually reduced the
    # record to its facts, so the claim and the record cannot diverge.
    r"metadata index|"
    # GODL-India (Government Open Data License - India), the licence on data.gov.in.
    # It permits use, adaptation and derivative works "for all lawful commercial
    # and non-commercial purposes" with attribution -- clearly commercial. See
    # docs/sources/legal_scope.md, which lists data.gov.in as allowed.
    r"godl|government open data license"
    r")\b"
)


def classify_license(raw: str | None) -> tuple[bool, str]:
    """Return ``(commercial_ok, reason)`` for a free-text license string.

    Default-deny: an empty string is ``"missing license"`` and anything that
    matches no allow pattern is ``"unrecognized license: <raw>"``.
    """
    if raw is None or not str(raw).strip():
        return False, "missing license"
    s = " ".join(str(raw).strip().lower().split())

    deny = _DENY.search(s)
    if deny:
        return False, f"non-commercial/copyleft license ({deny.group(1)})"

    allow = _ALLOW.search(s)
    if allow:
        return True, f"commercial-ok ({allow.group(1)})"

    return False, f"unrecognized license: {raw!r}"


def license_verdict(raw: str | None) -> Literal["ok", "blocked", "unknown"]:
    """Three-state license verdict for a free-text license string.

    Unlike :func:`classify_license` (default-deny: blank/unrecognized both count
    as "not commercial-ok"), this separates a **confirmed-restrictive** license
    from a merely *absent or unrecognized* one:

    - ``"blocked"`` only when a deny pattern matches (copyleft / non-commercial /
      share-alike / proprietary / all-rights-reserved) - a *confirmed red* license.
    - ``"ok"`` when an allow pattern matches (clearly-commercial permissive).
    - ``"unknown"`` for blank or unrecognized text.

    The blacklist keys on ``"blocked"`` so a source is never blacklisted for a
    missing/unknown license - only for one we positively recognise as red.
    """
    if raw is None or not str(raw).strip():
        return "unknown"
    s = " ".join(str(raw).strip().lower().split())
    if _DENY.search(s):
        return "blocked"
    if _ALLOW.search(s):
        return "ok"
    return "unknown"


# The only values that turn the gate off. Everything else, including anything
# unrecognized, leaves it on: see _enforced.
_OFF_VALUES = frozenset({"0", "false", "no", "off"})
_ON_VALUES = frozenset({"1", "true", "yes", "on"})


def _enforced() -> bool:
    """Whether the gate is active. Default on, and it fails closed.

    This switch decides whether a confirmed-red licence gets fetched, so a value
    it does not understand must never be read as "off". It used to test for
    membership of the *on* words and return False for anything else, which meant
    a typo (``yess``), a wrong-shaped value (``2``) or an empty assignment
    (``CYBERSEC_SLM_ENFORCE_LICENSE_GATE=``) silently disabled the gate for every
    source. Now only an explicit, recognized off value disables it; anything
    unrecognized enforces and says so, because a switch that quietly does the
    dangerous thing on a typo is worse than no switch.
    """
    env = os.environ.get("CYBERSEC_SLM_ENFORCE_LICENSE_GATE")
    if env is None:
        return True
    val = env.strip().lower()
    if val in _OFF_VALUES:
        return False
    if val not in _ON_VALUES:
        logger.warning(
            f"CYBERSEC_SLM_ENFORCE_LICENSE_GATE={env!r} is not a recognized "
            f"value; keeping the licence gate ON. Use one of "
            f"{sorted(_OFF_VALUES)} to disable it.")
    return True


def _descriptor_url(descriptor: dict) -> str:
    """The best URL to resolve a descriptor's license from (``""`` when it has none)."""
    for key in ("url", "start_url", "link", "dataset_link"):
        val = str(descriptor.get(key) or "").strip()
        if val:
            return val
    ref = str(descriptor.get("ref") or "").strip()
    if ref and descriptor.get("kind") == "hf":
        return f"https://huggingface.co/datasets/{ref}"
    return ""


# Deep detection is a network round-trip per source, and ingestion asks about the
# same URL more than once (the gate, then a retry, then a resumed run). Memoized
# per process: the license on a page does not change within a run, and the cache
# is what keeps the gate cheap enough to apply to every unknown row rather than
# just the two kinds it used to cover.
_DEEP_CACHE: dict[str, str] = {}


def deep_license(url: str) -> str:
    """Resolve ``url``'s license by fetching the source, or ``""`` if undeterminable.

    Delegates to :func:`cybersec_slm.sourcing.license_detect.detect_license`, which
    dispatches by host (HuggingFace card, GitHub API, Kaggle, arXiv, then generic
    ``<link rel=license>`` / JSON-LD / Creative-Commons / terms-of-use prose). Never
    raises: an unreachable or unreadable source yields ``""``, which leaves the
    caller's default-deny in place.
    """
    url = (url or "").strip()
    if not url:
        return ""
    if url in _DEEP_CACHE:
        return _DEEP_CACHE[url]
    try:
        from ..sourcing.license_detect import detect_license
        found = detect_license(url, github_token=os.environ.get("GITHUB_TOKEN")) or ""
    except Exception as e:                      # noqa: BLE001 - best-effort by contract
        logger.debug(f"deep_license: {url}: {type(e).__name__}: {e}")
        found = ""
    _DEEP_CACHE[url] = found
    return found


def is_license_ok(descriptor: dict) -> tuple[bool, str]:
    """Return ``(allowed, reason)`` for a source descriptor's license.

    Reads ``descriptor["license"]`` (the value ingestion actually fetches with, from
    the ``Sources.csv`` License column). Returns ``(True, "license-gate-disabled")``
    when the kill switch is set.

    When the catalog's license is blank or unrecognized, this is where the **deep
    check** happens: the source itself is fetched and its stated terms classified
    (:func:`deep_license`). Sourcing deliberately admits license-unsure rows —
    including ones from hosts on a profile's restricted list — so that this gate,
    which can see the actual page, is the thing that decides. A source whose terms
    still cannot be read stays denied: unknown is never treated as permission.
    """
    if not _enforced():
        return True, "license-gate-disabled"

    lic_str = descriptor.get("license")

    # 1. The catalog's own string, when it is already conclusive either way.
    verdict = license_verdict(lic_str)
    if verdict == "ok":
        return True, classify_license(lic_str)[1]
    if verdict == "blocked":
        return False, classify_license(lic_str)[1]

    # 2. Unknown or missing -> go and read the source's actual terms.
    url = _descriptor_url(descriptor)
    fetched = deep_license(url)
    if fetched:
        allowed, reason = classify_license(fetched)
        logger.info(f"license deep-check {url}: {fetched!r} -> "
                    f"{'allowed' if allowed else 'denied'} ({reason})")
        return allowed, f"deep-check: {reason}"

    # 3. Still unresolved: default-deny, and say that the deep check was tried so
    # the reason distinguishes "we looked and found nothing" from "we never looked".
    return False, (f"unresolved license after deep check: {url}" if url
                   else classify_license(lic_str)[1])
