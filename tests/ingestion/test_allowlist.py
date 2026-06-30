"""Tests for the version-controlled source allowlist gate."""

from __future__ import annotations

import pytest

from cybersec_slm.ingestion import allowlist


@pytest.fixture(autouse=True)
def _clear_cache():
    allowlist.load_allowlist.cache_clear()
    yield
    allowlist.load_allowlist.cache_clear()


def _write(tmp_path, body):
    p = tmp_path / "allowlist.yaml"
    p.write_text(body, encoding="utf-8")
    return str(p)


def test_descriptor_key_shapes():
    assert allowlist.descriptor_key({"kind": "hf", "ref": "org/ds"}) == "hf:org/ds"
    assert allowlist.descriptor_key(
        {"kind": "url", "url": "https://x/y.zip"}) == "https://x/y.zip"
    assert allowlist.descriptor_key(
        {"kind": "website", "start_url": "https://s/", "slug": "s"}) == "https://s/"


def test_approved_source_allowed(tmp_path):
    path = _write(tmp_path, """
version: 1
enforce: true
sources:
  - id: hf:org/ds
    status: approved
""")
    ok, reason = allowlist.is_allowed({"kind": "hf", "ref": "org/ds"}, path=path)
    assert ok and reason == "approved"


def test_pending_and_unknown_blocked(tmp_path):
    path = _write(tmp_path, """
version: 1
enforce: true
sources:
  - id: hf:org/pending
    status: pending
""")
    ok, _ = allowlist.is_allowed({"kind": "hf", "ref": "org/pending"}, path=path)
    assert ok is False
    ok2, _ = allowlist.is_allowed({"kind": "hf", "ref": "org/unknown"}, path=path)
    assert ok2 is False


def test_url_fallback_match(tmp_path):
    path = _write(tmp_path, """
version: 1
enforce: true
sources:
  - id: some-slug
    url: https://example.org/data.zip
    status: approved
""")
    ok, _ = allowlist.is_allowed(
        {"kind": "url", "url": "https://example.org/data.zip"}, path=path)
    assert ok


def test_missing_file_fails_open(tmp_path):
    missing = str(tmp_path / "nope.yaml")
    ok, reason = allowlist.is_allowed({"kind": "hf", "ref": "x/y"}, path=missing)
    assert ok and reason == "allowlist-disabled"


def test_env_force_enforce_on_missing_file(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_ENFORCE_ALLOWLIST", "1")
    allowlist.load_allowlist.cache_clear()
    missing = str(tmp_path / "nope.yaml")
    ok, _ = allowlist.is_allowed({"kind": "hf", "ref": "x/y"}, path=missing)
    assert ok is False


def test_dump_roundtrips(tmp_path):
    ds = [{"kind": "hf", "ref": "org/ds", "domain": "Cryptography",
           "license": "mit", "url": "https://hf/org/ds"}]
    text = allowlist.dump_allowlist_yaml(ds)
    path = _write(tmp_path, text)
    ok, _ = allowlist.is_allowed(ds[0], path=path)
    assert ok
