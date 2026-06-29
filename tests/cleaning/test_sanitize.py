from cybersec_slm.cleaning import sanitize


def test_normalizes_existing_fields_without_fabricating():
    # None-valued existing fields are normalized to ""; missing provenance fields
    # are NOT invented (the normalize mappers supply those defaults).
    rec, changed = sanitize.sanitize_record({"source": None, "text": "hello world"})
    assert changed                       # source None -> ""
    assert rec["source"] == ""
    assert rec["text"] == "hello world"
    assert "url" not in rec and "license" not in rec

    # a clean record with no None fields is unchanged
    rec2, changed2 = sanitize.sanitize_record({"text": "hello world"})
    assert changed2 is False
    assert rec2 == {"text": "hello world"}


def test_strips_control_chars_and_collapses_whitespace():
    rec, _ = sanitize.sanitize_record({"text": "a\x00b\x07c    d\t\te"})
    assert rec["text"] == "abc d e"


def test_normalizes_crlf_and_blank_lines():
    rec, _ = sanitize.sanitize_record({"text": "line1\r\n\r\n\r\n\r\nline2"})
    assert rec["text"] == "line1\n\nline2"


def test_unicode_nfc():
    # 'e' + combining acute accent -> single NFC codepoint 'é'
    rec, _ = sanitize.sanitize_record({"text": "café " + "x" * 10})
    assert "é" in rec["text"]          # é
    assert "́" not in rec["text"]      # combining mark gone


def test_unambiguous_date_to_iso():
    rec, changed = sanitize.sanitize_record(
        {"text": "x" * 60, "date": "January 5, 2021"})
    assert rec["date"] == "2021-01-05"
    assert changed


def test_iso_date_passthrough():
    rec, _ = sanitize.sanitize_record({"text": "x" * 60, "date": "2021-01-05"})
    assert rec["date"] == "2021-01-05"
