"""Per-source worker gating: allowlist + license checks run before any fetch."""

from __future__ import annotations

import pytest

from cybersec_slm.ingestion import worker


@pytest.fixture
def _allow_everything(monkeypatch):
    """Neutralize the source allowlist so tests isolate the license gate."""
    monkeypatch.setattr(worker, "is_allowed", lambda d: (True, "approved"))


def _spy_fetch(monkeypatch):
    """Replace _fetch_one with a spy that records whether it was invoked."""
    calls: list[dict] = []

    def _fake(descriptor, log):
        calls.append(descriptor)
        return "unused-folder"

    monkeypatch.setattr(worker, "_fetch_one", _fake)
    return calls


def test_non_commercial_license_is_skipped_before_fetch(_allow_everything, monkeypatch):
    calls = _spy_fetch(monkeypatch)
    descriptor = {"kind": "hf", "ref": "org/ds", "domain": "Cryptography",
                  "license": "GPL-3.0", "description": "", "url": "https://hf/org/ds"}

    result = worker.process_source(descriptor)

    assert result["status"] == "skipped"
    assert result["error"].startswith("license:")
    assert calls == []                       # never fetched


def test_commercial_license_passes_the_gate(_allow_everything, monkeypatch):
    calls = _spy_fetch(monkeypatch)
    # Stop after the fetch: folder doesn't exist on disk, so no cleaning runs.
    monkeypatch.setattr(worker.os.path, "isdir", lambda p: False)
    descriptor = {"kind": "hf", "ref": "org/ds", "domain": "Cryptography",
                  "license": "MIT", "description": "", "url": "https://hf/org/ds"}

    result = worker.process_source(descriptor)

    assert result["status"] == "ok"
    assert len(calls) == 1                    # license passed -> fetch attempted


def test_kill_switch_lets_any_license_through(_allow_everything, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_ENFORCE_LICENSE_GATE", "0")
    calls = _spy_fetch(monkeypatch)
    monkeypatch.setattr(worker.os.path, "isdir", lambda p: False)
    descriptor = {"kind": "hf", "ref": "org/ds", "domain": "Cryptography",
                  "license": "GPL-3.0", "description": "", "url": "https://hf/org/ds"}

    result = worker.process_source(descriptor)

    assert result["status"] == "ok"
    assert len(calls) == 1                    # gate disabled -> fetched despite GPL
