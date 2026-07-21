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
  * API_KEY      — vendor-prefixed secrets only (AWS/GitHub/Slack/Google/Stripe
                   key ids, JWTs). A fixed issuer prefix makes the span a
                   credential by construction, not by guess.
  * PRIVATE_KEY  — a whole PEM private-key block.
  * MAC_ADDRESS  — six hex pairs, anchored so it cannot match inside a hash.
  * USERNAME     — the name component of a filesystem path (``/home/<x>``,
                   ``C:\\Users\\<x>``); the path structure is kept.
  * IN_PAN       — India PAN (5 letters, 4 digits, 1 letter).
  * AADHAAR      — India Aadhaar: 12 digits, Verhoeff-checksummed AND next to an
                   Aadhaar/UIDAI cue. A bare 12-digit run is far too common here
                   (transaction ids, offsets) to redact on shape alone.

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


# --- credentials / device / national-ID patterns -----------------------------
# Everything here is deliberately HIGH-SIGNAL: a fixed vendor prefix, a checksum,
# or a required context cue. The module's rule is that a redaction must be
# assertable from the span itself, because a false positive silently destroys
# corpus text (see the IP/credit-card notes above).
#
# Deliberately NOT added, though docs/pii_limitations.md lists them:
#   * private/RFC1918 IPs — kept on purpose (teaching value; see _ip_ok)
#   * internal hostnames  — "dc01.corp.internal" has no assertable shape; a
#     pattern loose enough to catch it eats ordinary dotted identifiers
#   * ticket ids (INC0042317) — site-specific, and indistinguishable from the
#     many other alphanumeric identifiers a security corpus is full of

# Vendor-prefixed secrets. Each prefix is issued by exactly one provider, so a
# match is a credential by construction rather than by guess.
_SECRET = re.compile(
    r"\b("
    r"(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}"      # AWS key id
    r"|gh[pousr]_[A-Za-z0-9]{36,255}"                                # GitHub token
    r"|github_pat_[A-Za-z0-9_]{22,255}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"                                 # Slack
    r"|AIza[0-9A-Za-z_-]{35}"                                        # Google API key
    r"|(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{10,}"                     # Stripe
    r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"   # JWT
    r")\b")

# A PEM private-key block header — the body is redacted with it.
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"
    r".*?-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
    re.DOTALL)

# MAC address: six hex pairs, colon- or hyphen-separated. Anchored so it cannot
# match inside a longer hex run (a hash, a byte dump).
_MAC = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"
                  r"(?![0-9A-Fa-f:-])")

# A username sitting in a filesystem path. Only the name component is replaced,
# so the path structure (which is what makes the text useful) survives.
_USER_PATH = re.compile(
    r"(?i)([A-Z]:\\Users\\|/home/|/Users/)([^\\/:*?\"<>|\r\n\s]{1,64})")

# India PAN: 5 letters, 4 digits, 1 letter. Distinctive enough to stand alone.
_PAN = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")

# India Aadhaar: 12 digits (never starting 0/1), optionally space/hyphen grouped.
# A bare 12-digit run is far too common in this corpus (transaction ids, offsets),
# so a match must ALSO pass the Verhoeff checksum AND sit near an Aadhaar cue —
# the same "looks like it is being used as one" discipline as _ip_redactable.
_AADHAAR = re.compile(r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)")
_AADHAAR_CUE = re.compile(r"(?i)\b(?:aadhaar|aadhar|uidai|uid)\b")
_AADHAAR_LOOKBACK = 60

_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6), (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4), (9, 8, 7, 6, 5, 4, 3, 2, 1, 0))
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2), (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8))


def _verhoeff_ok(digits: str) -> bool:
    """True when ``digits`` passes the Verhoeff checksum Aadhaar numbers carry."""
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def _aadhaar_redactable(m: re.Match) -> bool:
    digits = "".join(ch for ch in m.group(0) if ch.isdigit())
    if len(digits) != 12 or not _verhoeff_ok(digits):
        return False
    before = m.string[max(0, m.start() - _AADHAAR_LOOKBACK):m.start()]
    return bool(_AADHAAR_CUE.search(before))


def _user_path_sub(m: re.Match) -> str:
    """Keep the path prefix, replace only the username component."""
    return f"{m.group(1)}<USERNAME>"


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

    # Credentials first: a PEM block or a vendor-prefixed token can contain
    # substrings the later, looser patterns would otherwise nibble at.
    text = sub(_PRIVATE_KEY, "PRIVATE_KEY", text)
    text = sub(_SECRET, "API_KEY", text)
    text = sub(_EMAIL, "EMAIL_ADDRESS", text)
    text = sub(_SSN, "US_SSN", text, validator=lambda m: _ssn_ok(m.group(0)))
    text = sub(_AADHAAR, "AADHAAR", text, validator=_aadhaar_redactable)
    text = sub(_CC, "CREDIT_CARD", text, validator=lambda m: _cc_ok(m.group(0)))
    text = sub(_PAN, "IN_PAN", text)
    text = sub(_MAC, "MAC_ADDRESS", text)
    text = sub(_IPV4, "IP_ADDRESS", text, validator=_ip_redactable)

    # Username-in-path keeps its prefix, so it needs its own substitution rather
    # than the whole-span replacement `sub` does.
    text, n_paths = _USER_PATH.subn(_user_path_sub, text)
    count += n_paths
    return text, count


class Redactor:
    """Redact PII from text.

    ``engine`` defaults to ``$CYBERSEC_SLM_PII_ENGINE`` and then to ``"presidio"``,
    which runs a regex pass followed by a scoped NER pass (if text is short enough).
    If Presidio is not installed, it safely degrades to just regex.
    """

    def __init__(self, engine: str | None = None,
                 max_presidio_chars: int | None = None):
        requested = (engine or os.environ.get(_PII_ENGINE_ENV) or "presidio").strip().lower()
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
