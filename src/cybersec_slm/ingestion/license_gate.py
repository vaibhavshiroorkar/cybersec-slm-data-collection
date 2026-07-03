#!/usr/bin/env python3
"""Commercial-only license gate for ingestion.

A source is fetched only if its license clearly permits *unencumbered commercial
use*. This sits alongside the source allowlist (``allowlist.py``) as a second,
separately-logged ingestion gate: the allowlist answers "did we vet this exact
source?"; this answers "are we legally allowed to train commercially on it?".

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
(mirrors ``CYBERSEC_SLM_ENFORCE_ALLOWLIST``), for local dev/testing.

Public API:
    classify_license(raw)   -> (commercial_ok, reason)   # pure classifier
    is_license_ok(descriptor) -> (allowed, reason)       # + env kill switch
"""

from __future__ import annotations

import os
import re

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
# CC0 / CC-BY-4.0 (the deny pass above has already removed -nc/-sa variants), and
# the named-entity terms present in this catalog that are free-to-use commercially
# (MITRE ATT&CK/CAPEC/CWE, IETF Trust). `mit` is boundary-matched so it does not
# fire inside "permit"/"limited".
_ALLOW = re.compile(
    r"\b("
    r"mit|apache|bsd|cc0|cdla[- ]permissive|"
    r"public domain|us[- ]gov|u\.s\. gov|government work|"
    r"mitre|ietf|cc[- ]by[- ]?4\.0|open access"
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


def _enforced() -> bool:
    """Whether the gate is active (default on; env can turn it off)."""
    env = os.environ.get("CYBERSEC_SLM_ENFORCE_LICENSE_GATE")
    if env is None:
        return True
    return env.strip().lower() in ("1", "true", "yes", "on")


def is_license_ok(descriptor: dict) -> tuple[bool, str]:
    """Return ``(allowed, reason)`` for a source descriptor's license.

    Reads ``descriptor["license"]`` (the value ingestion actually fetches with,
    from the ``Sources.csv`` License column) — not the point-in-time copy stored
    in ``allowlist.yaml``. Returns ``(True, "license-gate-disabled")`` when the
    kill switch is set.
    """
    if not _enforced():
        return True, "license-gate-disabled"
    return classify_license(descriptor.get("license"))
