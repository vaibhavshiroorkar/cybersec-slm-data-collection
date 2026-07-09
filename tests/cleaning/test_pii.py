from cybersec_slm.cleaning.pii import Redactor


class _FakeAnalyzer:
    """Stand-in for Presidio's analyzer that records whether it was called."""

    def __init__(self):
        self.calls = 0

    def analyze(self, text, language):   # noqa: ARG002
        self.calls += 1
        return []


def _presidio_stub(max_chars):
    r = Redactor(engine="regex", max_presidio_chars=max_chars)
    r.engine = "presidio"                      # force the presidio branch
    r._analyzer = _FakeAnalyzer()
    r._anonymizer = object()
    return r


def test_oversized_text_bypasses_presidio_uses_regex():
    r = _presidio_stub(max_chars=100)
    big = "x " * 200 + "email a@b.com"          # > 100 chars
    out, n = r.redact(big)
    assert r._analyzer.calls == 0               # Presidio never touched the blob
    assert "<EMAIL_ADDRESS>" in out             # regex fallback still redacted
    assert n >= 1


def test_small_text_still_uses_presidio():
    r = _presidio_stub(max_chars=10_000)
    r.redact("short text under the cap")
    assert r._analyzer.calls == 1               # within cap -> Presidio runs


def test_regex_redacts_common_identifiers():
    r = Redactor(engine="regex")
    text = ("Email a@b.com IP 10.0.0.1 SSN 123-45-6789 "
            "card 4111 1111 1111 1111 please respond soon.")
    out, n = r.redact(text)
    assert "<EMAIL_ADDRESS>" in out
    assert "<IP_ADDRESS>" in out
    assert "<US_SSN>" in out
    assert "<CREDIT_CARD>" in out
    assert n >= 4
    assert "a@b.com" not in out


def test_invalid_credit_card_not_redacted():
    r = Redactor(engine="regex")
    # fails the Luhn check -> left as-is
    out, n = r.redact("number 1234 5678 9012 3457 here")
    assert "<CREDIT_CARD>" not in out


def test_no_pii_returns_zero():
    r = Redactor(engine="regex")
    out, n = r.redact("a perfectly ordinary sentence with no identifiers")
    assert n == 0
    assert out == "a perfectly ordinary sentence with no identifiers"
