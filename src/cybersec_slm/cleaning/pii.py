#!/usr/bin/env python3
"""PII Removal — redact personally identifying information.

Regex is the primary engine. Redactions replace the span with a typed
placeholder, e.g. <EMAIL_ADDRESS>.

Scope is narrow on purpose — only identifiers a regex can assert with confidence:

  * EMAIL_ADDRESS
  * IP_ADDRESS   — public addresses only. RFC1918/loopback/link-local/multicast
                   and the TEST-NET documentation ranges are not PII and carry
                   real teaching value in security text, so they are kept.
  * CREDIT_CARD  — issuer (IIN) prefix AND Luhn AND a real card length. Luhn
                   alone passes ~1 in 10 random digit runs, which is untenable in
                   a corpus of hashes, offsets and identifiers.
  * US_SSN       — structurally valid area/group/serial only.

Phone numbers are deliberately NOT matched. FineWeb excluded them for their false
positive rate, and here the pattern was eating timestamps' fractional seconds
(``15:55:14.0647632`` -> ``<PHONE_NUMBER>``).

Why regex is primary (this file used to run Presidio + spaCy on every record):
Presidio was measured at ~135 ms/record — 95.6% of the entire clean stage — and
it anonymized *every* span its default recognizer set returned, so on this corpus
99% of removed characters were not PII. It rewrote
``2024-07-15 15:55:14.0647632`` into ``<DATE_TIME> 15:55:14.<PHONE_NUMBER>``, and
the identical field into ``<US_DRIVER_LICENSE>`` on the next record; it read
``SIEM`` as a LOCATION and ``n1``/``n2`` as driver's licences, and it destroyed
URLs wholesale. FineWeb (15T tokens) and Dolma (3T tokens) both use regex for PII;
neither uses NER.

The ``presidio`` engine (opt-in, ``--pii-engine presidio`` / the Clean page's
advanced settings) is kept for a deliberate audit pass. It is **additive and
scoped**: the regex pass still does the structured identifiers, and Presidio is
asked ONLY for :data:`_NER_ENTITIES` — so the entity types that caused the
corruption above can never be redacted again, whichever engine is selected.
It costs ~68-135 ms/record, i.e. ~300x the regex path.

A gated hybrid ("run NER only when regex hits") was measured and rejected: person
names carry no regex signature, so the gate missed 42% of real PERSON spans while
still costing 110x the regex path — a leaky privacy control is worse than an
honest one. Note also that on this corpus PERSON is overwhelmingly public author
bylines (NIST/RFC attribution), which is citation rather than PII; that is why
redacting names is opt-in rather than the default.

Public API:
    r = Redactor()                  # engine from $CYBERSEC_SLM_PII_ENGINE, default regex
    new_text, n = r.redact(text)    # n = number of spans redacted
"""

from __future__ import annotations

import ipaddress
import os
import re

from .common import logger, try_import

# Read from the environment, not a module global: the clean stage runs in SPAWNED
# pool workers that re-import this module fresh, so a parent-process assignment
# would never reach them. ``cli.py`` sets this env var, which children inherit.
_PII_ENGINE_ENV = "CYBERSEC_SLM_PII_ENGINE"
PII_ENGINES = ("regex", "presidio")

# The ONLY entity Presidio is ever asked for. Everything the regex pass already
# does correctly is left to it (Presidio's own IP recognizer cannot tell a public
# address from 127.0.0.1, and its CREDIT_CARD/US_SSN fire on ZIP+4s and offsets).
# Keeping this list to PERSON is what makes the opt-in safe: URL, DATE_TIME,
# LOCATION, NRP and US_DRIVER_LICENSE are structurally unable to be redacted.
_NER_ENTITIES = ["PERSON"]


# Presidio runs spaCy NER over the *entire* text, so cost grows with length.
# Oversized records (e.g. smart-contract source+bytecode blobs) are pure
# structured payloads with no prose PII, yet dominate the pass. Above this many
# characters the NER step is skipped; the regex pass still runs in O(n).
def _pii_max_presidio_chars() -> int:
    try:
        return int(os.environ.get("CYBERSEC_SLM_PII_MAX_CHARS", 10_000))
    except (TypeError, ValueError):
        return 10_000

# --- patterns (order matters: specific -> generic) ---
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
# Candidate digit runs; _cc_ok does the real work (IIN + Luhn + length).
_CC = re.compile(r"\b(?:\d[ -]?){13,19}\b")
# Anchored so a dotted-quad inside a longer version string ("v1.2.3.4",
# "1.2.3.4.5") is not mistaken for an address, while an address ending a
# sentence ("...to 8.8.8.8.") still matches.
_IPV4 = re.compile(
    r"(?<![\w.])"
    r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?!\.?\d)")

# Issuer identification numbers: Visa 4, Mastercard 51-55 and 2221-2720,
# Amex 34/37, Discover 6011/65/644-649.
_CC_IIN = re.compile(
    r"(?:"
    r"4"
    r"|5[1-5]"
    r"|2(?:2(?:2[1-9]|[3-9]\d)|[3-6]\d\d|7(?:[01]\d|20))"
    r"|3[47]"
    r"|6(?:011|5|4[4-9])"
    r")")
_CC_LENGTHS = frozenset({13, 15, 16, 19})


def _luhn_ok(digits: str) -> bool:
    ds = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(ds) <= 19:
        return False
    total, alt = 0, False
    for d in reversed(ds):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _cc_ok(span: str) -> bool:
    """True only for a plausible card: real length, issuer prefix, Luhn."""
    digits = "".join(c for c in span if c.isdigit())
    if len(digits) not in _CC_LENGTHS:
        return False
    if not _CC_IIN.match(digits):
        return False
    return _luhn_ok(digits)


def _ssn_ok(span: str) -> bool:
    """True for a structurally issuable SSN (SSA never issues these patterns)."""
    try:
        area, group, serial = span.split("-")
    except ValueError:
        return False
    if area in ("000", "666") or area.startswith("9"):
        return False
    return group != "00" and serial != "0000"


def _ip_ok(span: str) -> bool:
    """True only for a globally routable address (see module docstring)."""
    try:
        ip = ipaddress.IPv4Address(span)
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


# A dotted quad being *routable* is not enough to make it an address. In this
# corpus the identical shape is also a document section number ("3.4.3.1 Mosca's
# Theorem" — and 3.0.0.0/8 really is Amazon, so is_global says yes) and a software
# version ("14.x through 18.x before 18.0.0.194"). Redacting those destroys the
# structure of exactly the NIST/RFC standards this corpus is built from, so a
# match must also LOOK like an address in use.
#
# A network cue anywhere nearby is not sufficient on its own either: section
# titles in a security corpus are full of networking words ("4.1.4.1 Network
# Discovery Analysis"), which is why the vetoes are checked first.
_IP_PORT_OR_PATH = re.compile(r"\A(?::\d{1,5}(?!\d)|/)")
_IP_VETO_BEFORE = re.compile(
    r"(?i)\b(?:before|after|through|thru|prior\s+to|since|up\s+to|until|version|"
    r"ver|rev|release|build|section|sec|clause|appendix|figure|fig|table|chapter|"
    r"item|step|part|paragraph|para)\s*\.?\s*\Z")
# "3.4.3.1 Mosca's Theorem": a quad followed by a Title-Case word is a heading.
_IP_VETO_AFTER = re.compile(r"\A\s+[A-Z][a-z]")
_IP_CUE_BEFORE = re.compile(
    r"(?i)\b(?:ip|ips|ipv4|addr|address|addresses|host|hostname|server|src|dst|"
    r"source|dest|destination|gateway|dns|resolver|subnet|cidr|ping|curl|wget|ssh|"
    r"telnet|http|https|tcp|udp|icmp|port|c2|beacon|attacker|victim|inet|nmap|"
    r"route|firewall|proxy|endpoint|remote|client|traffic|packet|resolve|connect|"
    r"blocklist|blacklist|allowlist|ioc|indicator|node)\b")

_IP_LOOKBACK = 40


def _ip_redactable(m: re.Match) -> bool:
    """True when the match is a public address *used as* an address."""
    if not _ip_ok(m.group(0)):
        return False
    text = m.string
    before = text[max(0, m.start() - _IP_LOOKBACK):m.start()]
    after = text[m.end():m.end() + 20]
    # An explicit port/CIDR/path is decisive on its own ("8.8.8.8:53").
    if _IP_PORT_OR_PATH.match(after):
        return True
    if _IP_VETO_BEFORE.search(before) or _IP_VETO_AFTER.match(after):
        return False
    if before[-1:] in "'\"" and after[:1] in "'\"":
        return True
    return bool(_IP_CUE_BEFORE.search(before))


def _regex_redact(text: str) -> tuple[str, int]:
    count = 0

    def sub(pattern, label, s, validator=None):
        nonlocal count

        # The validator takes the MATCH, not the matched string: deciding whether
        # a dotted quad is an address needs the surrounding text (see
        # _ip_redactable), which only the match object carries.
        def repl(m):
            nonlocal count
            if validator and not validator(m):
                return m.group(0)
            count += 1
            return f"<{label}>"

        return pattern.sub(repl, s)

    text = sub(_EMAIL, "EMAIL_ADDRESS", text)
    text = sub(_SSN, "US_SSN", text, validator=lambda m: _ssn_ok(m.group(0)))
    text = sub(_CC, "CREDIT_CARD", text, validator=lambda m: _cc_ok(m.group(0)))
    text = sub(_IPV4, "IP_ADDRESS", text, validator=_ip_redactable)
    return text, count


class Redactor:
    """Redact PII from text.

    ``engine`` defaults to ``$CYBERSEC_SLM_PII_ENGINE`` and then to ``"regex"``,
    which needs no models and builds instantly. ``"presidio"`` adds a scoped NER
    pass for person names on top of the regex pass (see the module docstring for
    the cost); if Presidio is not installed the request degrades to regex with a
    warning rather than failing a run mid-flight.
    """

    def __init__(self, engine: str | None = None,
                 max_presidio_chars: int | None = None):
        requested = (engine or os.environ.get(_PII_ENGINE_ENV) or "regex").strip().lower()
        self.engine = "regex"
        self._analyzer = None
        self._anonymizer = None
        self.max_presidio_chars = (max_presidio_chars if max_presidio_chars is not None
                                   else _pii_max_presidio_chars())
        if requested not in PII_ENGINES:
            logger.warning(f"pii: unknown engine {requested!r}; using regex")
            return
        if requested == "presidio":
            pa = try_import("presidio_analyzer")
            pan = try_import("presidio_anonymizer")
            if pa is None or pan is None:
                logger.warning(
                    "pii: engine 'presidio' requested but presidio is not installed "
                    "(uv sync --extra pii-ner); using regex")
                return
            try:
                self._analyzer = pa.AnalyzerEngine()
                self._anonymizer = pan.AnonymizerEngine()
                self.engine = "presidio"
            except Exception as ex:                # model not downloaded, etc.
                logger.warning(f"pii: presidio init failed ({type(ex).__name__}); "
                               "using regex")
        logger.debug(f"pii: engine = {self.engine}")

    def _ner_redact(self, text: str) -> tuple[str, int]:
        """Scoped Presidio pass: person names only (see :data:`_NER_ENTITIES`)."""
        results = self._analyzer.analyze(text=text, language="en",
                                         entities=_NER_ENTITIES)
        if not results:
            return text, 0
        out = self._anonymizer.anonymize(text=text, analyzer_results=results)
        return out.text, len(results)

    def redact(self, text: str) -> tuple[str, int]:
        if not text:
            return text, 0
        # The regex pass always runs: it owns the structured identifiers and is
        # the only thing that distinguishes a public IP from 127.0.0.1.
        text, n = _regex_redact(text)
        if self.engine == "presidio" and len(text) <= self.max_presidio_chars:
            text, n_ner = self._ner_redact(text)
            n += n_ner
        return text, n
