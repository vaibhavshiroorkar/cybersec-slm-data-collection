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

Public API:
    classify_license(raw)   -> (commercial_ok, reason)   # pure classifier
    license_verdict(raw)    -> "ok" | "blocked" | "unknown"  # 3-state
    is_license_ok(descriptor) -> (allowed, reason)       # + env kill switch
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
    r"metadata index"
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


def is_license_ok(descriptor: dict) -> tuple[bool, str]:
    """Return ``(allowed, reason)`` for a source descriptor's license.

    Reads ``descriptor["license"]`` (the value ingestion actually fetches with,
    from the ``Sources.csv`` License column). Returns ``(True,
    "license-gate-disabled")`` when the kill switch is set.
    """
    if not _enforced():
        return True, "license-gate-disabled"
    return classify_license(descriptor.get("license"))
