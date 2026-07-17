from cybersec_slm.cleaning import anomaly, common
from cybersec_slm.cleaning.common import MAX_TEXT_CHARS


def test_empty_text_is_structural():
    bucket, _ = anomaly.classify({"text": ""})
    assert bucket == "structural"


def test_missing_text_is_structural():
    bucket, _ = anomaly.classify({"source": "x"})
    assert bucket == "structural"


def test_short_text_is_structural():
    bucket, _ = anomaly.classify({"text": "too short"})
    assert bucket == "structural"


def test_parse_error_is_structural():
    bucket, reason = anomaly.classify({"_parse_error": True})
    assert bucket == "structural" and "parse" in reason


def test_clean_paragraph():
    text = ("The quick brown fox jumps over the lazy dog and then runs back "
            "to the den for a long rest in the warm afternoon sun today.")
    bucket, _ = anomaly.classify({"text": text})
    assert bucket == "clean"


def test_repeated_lines_are_behavioral():
    text = "\n".join(["same boilerplate line here"] * 20)
    bucket, reason = anomaly.classify({"text": text})
    assert bucket == "behavioral"


def test_garbage_ratio_is_behavioral():
    text = "█" * 200
    bucket, reason = anomaly.classify({"text": text})
    assert bucket == "behavioral" and "garbage" in reason


def test_garbage_ratio_keeps_non_ascii_alphanumerics_clean():
    """Accented/CJK/Cyrillic letters are alphanumeric, not garbage — the fast
    translate path must not count them just because they are non-ASCII."""
    for text in ("café résumé naïve " * 20, "中文测试内容 " * 20, "Привет мир " * 20):
        assert anomaly.garbage_ratio(text) == 0.0


def test_garbage_ratio_counts_binary_noise():
    assert anomaly.garbage_ratio("\x00\x01\x02binary") == 3 / 9
    assert anomaly.garbage_ratio("") == 0.0
    assert anomaly.garbage_ratio("a=b[0]; x->y (n%2)==0 /* c */") == 0.0


def test_extreme_length_is_behavioral():
    text = "word " * (MAX_TEXT_CHARS // 2)        # well over the char cap
    bucket, reason = anomaly.classify({"text": text})
    assert bucket == "behavioral" and "length" in reason


def test_min_text_chars_override_takes_effect():
    """A settings-driven override of common.MIN_TEXT_CHARS must actually change
    anomaly's behavior (regression test for the module-global import-binding bug:
    anomaly.py used to `from .common import MIN_TEXT_CHARS`, which froze the value
    at import time and silently ignored any later override)."""
    original = common.MIN_TEXT_CHARS
    try:
        common.MIN_TEXT_CHARS = 5
        bucket, _ = anomaly.classify({"text": "short"})
        assert bucket == "clean"
    finally:
        common.MIN_TEXT_CHARS = original
