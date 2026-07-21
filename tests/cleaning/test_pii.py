from cybersec_slm.cleaning import pii
from cybersec_slm.cleaning.pii import Redactor


def _luhn_complete(body: str) -> str:
    """`body` + the check digit that makes it pass Luhn (test data builder)."""
    total, alt = 0, True
    for d in reversed([int(c) for c in body]):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return body + str((10 - total % 10) % 10)


def test_engine_is_regex_by_default():
    assert Redactor().engine == "regex"


# --- the presidio opt-in ------------------------------------------------------

class _FakeAnalyzer:
    """Records what Presidio was asked for, and returns one PERSON span."""

    def __init__(self):
        self.calls = 0
        self.entities_asked = None

    def analyze(self, text, language, entities=None):   # noqa: ARG002
        self.calls += 1
        self.entities_asked = entities
        start = text.find("Ada Lovelace")
        if start < 0:
            return []
        return [_Span(start, start + len("Ada Lovelace"))]


class _Span:
    def __init__(self, start, end):
        self.start, self.end, self.entity_type, self.score = start, end, "PERSON", 0.85


class _FakeAnonymizer:
    def anonymize(self, text, analyzer_results):
        out = text
        for r in sorted(analyzer_results, key=lambda r: -r.start):
            out = out[:r.start] + "<PERSON>" + out[r.end:]
        return type("R", (), {"text": out})()


def _presidio_stub(**kw):
    r = Redactor(**kw)
    r.engine = "presidio"
    r._analyzer = _FakeAnalyzer()
    r._anonymizer = _FakeAnonymizer()
    return r


def test_engine_reads_env(monkeypatch):
    """Spawned clean workers re-import the module, so the engine must travel by
    environment variable, not a parent-process global."""
    monkeypatch.setenv("CYBERSEC_SLM_PII_ENGINE", "regex")
    assert Redactor().engine == "regex"


def test_unknown_engine_falls_back_to_regex(monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_PII_ENGINE", "nonsense")
    assert Redactor().engine == "regex"


def test_presidio_requested_but_missing_degrades_to_regex(monkeypatch):
    monkeypatch.setattr(pii, "try_import", lambda name: None)
    r = Redactor(engine="presidio")
    assert r.engine == "regex"          # a run must not die mid-flight


def test_presidio_engine_only_ever_asks_for_person():
    """The corruption came from Presidio's default recognizer set. Whichever
    engine is chosen, URL/DATE_TIME/LOCATION/US_DRIVER_LICENSE must be
    structurally unreachable."""
    r = _presidio_stub()
    r.redact("contact Ada Lovelace today")
    assert r._analyzer.entities_asked == ["PERSON"]


def test_presidio_engine_redacts_person_on_top_of_regex():
    r = _presidio_stub()
    out, n = r.redact("Ada Lovelace at a@b.com from host 8.8.8.8:443")
    assert "<PERSON>" in out
    assert "<EMAIL_ADDRESS>" in out      # regex pass still ran
    assert "<IP_ADDRESS>" in out
    assert n == 3


def test_presidio_engine_still_keeps_timestamps_and_private_ips():
    r = _presidio_stub()
    text = "2024-07-15 15:55:14.0647632 host 127.0.0.1 SIEM n1"
    out, n = r.redact(text)
    assert out == text
    assert n == 0


def test_oversized_text_skips_ner_but_still_regex_redacts():
    r = _presidio_stub(max_presidio_chars=100)
    big = "x " * 200 + "Ada Lovelace mail a@b.com"
    out, n = r.redact(big)
    assert r._analyzer.calls == 0        # NER never touched the blob
    assert "<EMAIL_ADDRESS>" in out      # regex still did its job
    assert n >= 1


def test_regex_redacts_common_identifiers():
    r = Redactor()
    # 8.8.8.8 is public, so it is PII-adjacent and redacted; see the private-IP
    # test for the addresses this corpus must keep.
    text = ("Email a@b.com IP 8.8.8.8 SSN 123-45-6789 "
            "card 4111 1111 1111 1111 please respond soon.")
    out, n = r.redact(text)
    assert "<EMAIL_ADDRESS>" in out
    assert "<IP_ADDRESS>" in out
    assert "<US_SSN>" in out
    assert "<CREDIT_CARD>" in out
    assert n >= 4
    assert "a@b.com" not in out


def test_no_pii_returns_zero():
    r = Redactor()
    out, n = r.redact("a perfectly ordinary sentence with no identifiers")
    assert n == 0
    assert out == "a perfectly ordinary sentence with no identifiers"


# --- regressions for the corruption the Presidio engine caused -----------------

def test_timestamp_is_not_redacted():
    """The bug that motivated the rewrite: high-precision timestamps were being
    turned into <PHONE_NUMBER>, and the SAME field into <US_DRIVER_LICENSE> on
    the next record."""
    r = Redactor()
    text = "2024-07-15 15:55:14.0647632 Log Cleared: Unknown"
    out, n = r.redact(text)
    assert out == text
    assert n == 0


def test_private_and_reserved_ips_are_kept():
    """Loopback/RFC1918/link-local addresses are not PII and are pedagogically
    essential in security text."""
    r = Redactor()
    for ip in ("127.0.0.1", "192.168.1.1", "10.0.0.5", "172.16.0.1",
               "169.254.1.1", "0.0.0.0", "255.255.255.255", "224.0.0.1"):
        text = f"connect to {ip} now"
        out, n = r.redact(text)
        assert out == text, f"{ip} should be kept"
        assert n == 0


def test_documentation_range_ips_are_kept():
    r = Redactor()
    for ip in ("192.0.2.1", "198.51.100.5", "203.0.113.9"):
        out, n = r.redact(f"see {ip}")
        assert "<IP_ADDRESS>" not in out, f"{ip} (TEST-NET) should be kept"


def test_public_ips_are_redacted():
    r = Redactor()
    for ip in ("8.8.8.8", "54.159.34.148", "134.69.47.130"):
        out, n = r.redact(f"beacon to {ip} observed")
        assert "<IP_ADDRESS>" in out, f"{ip} should be redacted"
        assert ip not in out


def test_version_strings_are_not_mistaken_for_ips():
    r = Redactor()
    for text in ("upgrade to v1.2.3.4 today", "build 1.2.3.4.5 shipped"):
        out, n = r.redact(text)
        assert out == text
        assert n == 0


def test_ip_at_end_of_sentence_still_redacted():
    r = Redactor()
    out, _ = r.redact("the beacon went to 8.8.8.8.")
    assert "<IP_ADDRESS>" in out


# --- a dotted quad is only an address when it is USED as one -------------------
# In a security corpus the same shape is also a document section number and a
# software version. These are drawn from real data/raw records.

def test_ip_with_a_port_is_redacted():
    r = Redactor()
    out, _ = r.redact("Firewall deny UDP traffic from 11.167.185.171:41468 to "
                      "134.69.47.130:717")
    assert out.count("<IP_ADDRESS>") == 2
    assert "11.167.185.171" not in out and "134.69.47.130" not in out


def test_ip_with_a_path_or_cidr_is_redacted():
    r = Redactor()
    assert "<IP_ADDRESS>" in r.redact("- '1.1.1.1/dns-query'")[0]
    assert "<IP_ADDRESS>" in r.redact("route via 8.8.8.8/32 here")[0]


def test_ip_after_a_network_cue_is_redacted():
    r = Redactor()
    for text in ("Source IP 45.33.32.156 seen", "host: 45.33.32.156",
                 "connect to server 45.33.32.156"):
        assert "<IP_ADDRESS>" in r.redact(text)[0], text


def test_document_section_numbers_are_not_ips():
    """NIST/RFC section headings look exactly like dotted quads, and 3.0.0.0/8 is
    genuinely public, so is_global alone accepts them."""
    r = Redactor()
    for text in ("|546 |3.2.2.2 Operational Systems and Assets",
                 "|723 |3.4.3.1 Mosca's Theorem",
                 "|891 |4.1.4.1 Network Discovery Analysis",
                 "5.1.7.2 Single-Factor Cryptographic Devices"):
        out, n = r.redact(text)
        assert out == text, f"section number redacted: {text!r} -> {out!r}"
        assert n == 0


def test_section_cross_reference_is_not_an_ip():
    r = Redactor()
    text = "the model described in Section 3.4.3.1 and CARAF described in Section 3.4.3.2"
    out, n = r.redact(text)
    assert out == text
    assert n == 0


def test_software_version_in_cve_text_is_not_an_ip():
    r = Redactor()
    text = "14.x through 18.x before 18.0.0.194 on Windows and OS X"
    out, n = r.redact(text)
    assert out == text
    assert n == 0


def test_bare_dotted_quad_with_no_address_context_is_kept():
    """The accepted recall cost of requiring a network shape: a bare quad in
    prose, with nothing marking it as an address, is left alone."""
    r = Redactor()
    text = "the value 54.159.34.148 appears in the table"
    out, n = r.redact(text)
    assert out == text
    assert n == 0


def test_security_terms_and_urls_are_kept():
    """Presidio classified 'SIEM' as LOCATION, 'n1' as US_DRIVER_LICENSE, and
    destroyed 145 URLs across 129 records."""
    r = Redactor()
    text = ("SIEM rules n1 n2 n3 documented at "
            "https://github.com/DinaDiaa/windows-event-log-investigation")
    out, n = r.redact(text)
    assert out == text
    assert n == 0


def test_phone_numbers_are_never_redacted():
    """Phone regex is removed on purpose: FineWeb excluded it for its false
    positive rate, and it was eating this corpus's timestamps."""
    r = Redactor()
    out, n = r.redact("call 555-123-4567 or +1 (415) 555-0100")
    assert "<PHONE_NUMBER>" not in out
    assert n == 0


# --- credit cards: IIN prefix AND Luhn ----------------------------------------

def test_invalid_credit_card_not_redacted():
    r = Redactor()
    out, _ = r.redact("number 1234 5678 9012 3457 here")   # fails Luhn
    assert "<CREDIT_CARD>" not in out


def test_luhn_passing_non_card_digits_not_redacted():
    """Luhn alone passes ~1 in 10 random digit runs. A 16-digit identifier with
    no card IIN prefix must survive - this corpus is full of hashes and IDs."""
    r = Redactor()
    fake = _luhn_complete("999888777666555")        # 16 digits, no valid IIN
    out, n = r.redact(f"object id {fake} logged")
    assert "<CREDIT_CARD>" not in out
    assert n == 0


def test_real_card_brands_are_redacted():
    r = Redactor()
    for card in ("4111111111111111",        # Visa
                 "5500005555555559",        # Mastercard
                 "378282246310005"):        # Amex
        out, _ = r.redact(f"paid with {card}")
        assert "<CREDIT_CARD>" in out, f"{card} should be redacted"


# --- SSN ----------------------------------------------------------------------

def test_valid_ssn_redacted():
    r = Redactor()
    out, n = r.redact("ssn 123-45-6789 on file")
    assert "<US_SSN>" in out
    assert n == 1


def test_structurally_invalid_ssns_kept():
    r = Redactor()
    for ssn in ("000-12-3456", "666-12-3456", "900-12-3456",
                "123-00-4567", "123-45-0000"):
        out, _ = r.redact(f"value {ssn}")
        assert "<US_SSN>" not in out, f"{ssn} is not a valid SSN"


def test_zip_plus_four_is_not_an_ssn():
    r = Redactor()
    text = "Gaithersburg, MD 20899-8930"
    out, n = r.redact(text)
    assert out == text
    assert n == 0


# ── credential / device / national-ID recognizers ────────────────────────────
# Each case is (text, must_be_redacted). The negative cases are the shapes this
# corpus actually contains and must survive: hashes, version strings, offsets.

import pytest

from cybersec_slm.cleaning.pii import Redactor as _R


def _redact(text):
    return _R(engine="regex").redact(text)


@pytest.mark.parametrize("text,label", [
    ("key AKIAIOSFODNN7EXAMPLE here", "API_KEY"),
    ("token ghp_" + "a" * 36 + " end", "API_KEY"),
    ("slack xoxb-1234567890-abcdefghij done", "API_KEY"),
    ("google AIza" + "B" * 35 + " done", "API_KEY"),
    ("stripe sk_live_abcdefghij1234 done", "API_KEY"),
    ("mac 00:1A:2B:3C:4D:5E here", "MAC_ADDRESS"),
    (r"path C:\Users\jsmith\Desktop", "USERNAME"),
    ("path /home/jsmith/logs", "USERNAME"),
    ("pan ABCDE1234F issued", "IN_PAN"),
])
def test_new_recognizers_redact(text, label):
    out, n = _redact(text)
    assert n >= 1 and f"<{label}>" in out


@pytest.mark.parametrize("text", [
    # A sha256 must not be mistaken for a MAC or a secret.
    "hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    # Version strings / section numbers stay intact.
    "upgrade from 1.2.3.4 to 18.0.0.194 per section 3.4.3.1",
    # A bare 12-digit id with no Aadhaar cue must survive.
    "transaction id 234567890123 posted",
    # Ordinary prose must be untouched.
    "The analyst reviewed the quarterly compliance report.",
])
def test_new_recognizers_do_not_fire_on_corpus_lookalikes(text):
    out, n = _redact(text)
    assert out == text and n == 0


def test_aadhaar_needs_checksum_and_cue():
    # 2341 2345 6783 is Verhoeff-valid; ...6784 is a deliberate near-miss.
    out, n = _redact("Aadhaar number 2341 2345 6783 on file")
    assert "<AADHAAR>" in out and n >= 1
    # Same number with NO cue -> kept (a bare 12-digit run is too common here).
    out2, _ = _redact("reference 2341 2345 6783 on file")
    assert "<AADHAAR>" not in out2
    # Cue present but checksum invalid -> kept.
    out3, _ = _redact("Aadhaar number 2341 2345 6784 on file")
    assert "<AADHAAR>" not in out3


def test_private_key_block_is_removed_whole():
    text = ("before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\nabc\n"
            "-----END RSA PRIVATE KEY-----\nafter")
    out, n = _redact(text)
    assert "<PRIVATE_KEY>" in out and "MIIEow" not in out and n >= 1
    assert out.startswith("before") and out.endswith("after")


def test_user_path_keeps_the_path_structure():
    out, _ = _redact(r"C:\Users\jsmith\Desktop\report.pdf")
    assert out == r"C:\Users\<USERNAME>\Desktop\report.pdf"
