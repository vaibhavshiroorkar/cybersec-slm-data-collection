"""AV scan gate: fail-closed on scan errors, quarantine on findings.

The spec says "reject/quarantine, never process anyway".  These tests prove
that the gate never silently passes a file it could not scan, and that a
positive finding triggers quarantine + raises ``Quarantined``.

Every test that touches clamd does so through mocks — no live container needed.
"""

import json
import os
import struct
from unittest import mock

import pytest

from cybersec_slm.ingestion import av_scan


# ──────────────────────────────────── helpers ─────────────────────────────────

def _write(tmp_path, name, body: bytes):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body)
    return str(p)


def _make_folder(tmp_path, files: dict[str, bytes] | None = None):
    """Create a temp source folder with the given files."""
    folder = tmp_path / "source"
    folder.mkdir(parents=True, exist_ok=True)
    for name, body in (files or {"data.txt": b"hello world"}).items():
        (folder / name).write_bytes(body)
    return str(folder)


class _FakeSocket:
    """Minimal mock of a clamd TCP socket for INSTREAM scanning."""

    def __init__(self, *, finding: str | None = None, raise_on_send: bool = False):
        self._finding = finding
        self._raise_on_send = raise_on_send

    def sendall(self, data: bytes):
        if self._raise_on_send:
            raise ConnectionResetError("clamd connection dropped mid-scan")

    def recv(self, bufsize: int) -> bytes:
        if self._finding:
            return f"stream: {self._finding} FOUND\0".encode()
        return b"stream: OK\0"

    def close(self):
        pass


# ──────────────────────────────── _enforced() ─────────────────────────────────

def test_enforced_defaults_to_on(monkeypatch):
    monkeypatch.delenv("CYBERSEC_SLM_ENFORCE_AV_SCAN", raising=False)

    assert av_scan._enforced() is True


def test_enforced_can_be_disabled(monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_ENFORCE_AV_SCAN", "0")

    assert av_scan._enforced() is False


# ─────────────────────────── noop when disabled ───────────────────────────────

def test_gate_is_noop_when_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERSEC_SLM_ENFORCE_AV_SCAN", "0")
    folder = _make_folder(tmp_path)

    assert av_scan.gate(folder) is True


def test_gate_file_is_noop_when_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERSEC_SLM_ENFORCE_AV_SCAN", "0")
    path = _write(tmp_path, "test.bin", b"anything")

    assert av_scan.gate_file(path) is True


# ───────────────────────── quarantine mechanics ──────────────────────────────

def test_quarantine_moves_folder_and_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(av_scan, "DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setattr(av_scan, "AV_LOG", str(tmp_path / "data" / "av.jsonl"))

    src = tmp_path / "raw" / "dom" / "src"
    src.mkdir(parents=True)
    (src / "f.txt").write_text("x")

    with pytest.raises(av_scan.Quarantined, match="Eicar"):
        av_scan.quarantine(str(src), "Eicar-Test-Signature")

    assert not src.exists(), "source folder should have been moved"
    # Quarantine log entry
    log_path = tmp_path / "data" / "av.jsonl"
    assert log_path.exists()
    entry = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert entry["finding"] == "Eicar-Test-Signature"
    assert entry["action"] == "quarantine_source"


def test_quarantine_file_moves_file_and_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(av_scan, "DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setattr(av_scan, "AV_LOG", str(tmp_path / "data" / "av.jsonl"))

    f = tmp_path / "test.bin"
    f.write_bytes(b"bad content")

    with pytest.raises(av_scan.Quarantined, match="Trojan"):
        av_scan.quarantine_file(str(f), "Trojan.Generic")

    assert not f.exists(), "file should have been moved"
    log_path = tmp_path / "data" / "av.jsonl"
    entry = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert entry["finding"] == "Trojan.Generic"
    assert entry["action"] == "quarantine_file"


# ─────────────── fail-closed: clamd unreachable ──────────────────────────────

def test_gate_raises_on_clamd_unreachable(monkeypatch, tmp_path):
    """With no clamd running, gate() must raise — never silently pass."""
    monkeypatch.delenv("CYBERSEC_SLM_ENFORCE_AV_SCAN", raising=False)
    folder = _make_folder(tmp_path)

    with pytest.raises(RuntimeError, match="clamd is not reachable"):
        av_scan.gate(folder)


def test_gate_file_raises_on_clamd_unreachable(monkeypatch, tmp_path):
    monkeypatch.delenv("CYBERSEC_SLM_ENFORCE_AV_SCAN", raising=False)
    path = _write(tmp_path, "test.bin", b"content")

    with pytest.raises(RuntimeError, match="clamd is not reachable"):
        av_scan.gate_file(path)


# ──────────── fail-closed: unreadable file ───────────────────────────────────

def test_gate_file_raises_scan_error_on_unreadable(monkeypatch, tmp_path):
    """A file that can't be read is a ScanError, not a silent False."""
    monkeypatch.delenv("CYBERSEC_SLM_ENFORCE_AV_SCAN", raising=False)
    path = str(tmp_path / "nonexistent.bin")

    with pytest.raises(av_scan.ScanError, match="could not read"):
        av_scan.gate_file(path)


# ──────────── fail-closed: mid-scan failure ──────────────────────────────────

def test_gate_raises_scan_error_on_mid_scan_failure(monkeypatch, tmp_path):
    """When _scan_stream raises mid-scan, gate() must raise ScanError."""
    monkeypatch.delenv("CYBERSEC_SLM_ENFORCE_AV_SCAN", raising=False)
    folder = _make_folder(tmp_path)

    bad_sock = _FakeSocket(raise_on_send=True)
    monkeypatch.setattr(av_scan, "_client", lambda: bad_sock)

    with pytest.raises(av_scan.ScanError, match="could not scan"):
        av_scan.gate(folder)


def test_gate_file_raises_scan_error_on_mid_scan_failure(monkeypatch, tmp_path):
    """When _scan_stream raises mid-scan, gate_file() must raise ScanError."""
    monkeypatch.delenv("CYBERSEC_SLM_ENFORCE_AV_SCAN", raising=False)
    path = _write(tmp_path, "test.bin", b"content")

    bad_sock = _FakeSocket(raise_on_send=True)
    monkeypatch.setattr(av_scan, "_client", lambda: bad_sock)

    with pytest.raises(av_scan.ScanError, match="could not scan"):
        av_scan.gate_file(path)


# ───────────── positive finding: quarantine ──────────────────────────────────

def test_gate_quarantines_on_finding(monkeypatch, tmp_path):
    monkeypatch.delenv("CYBERSEC_SLM_ENFORCE_AV_SCAN", raising=False)
    monkeypatch.setattr(av_scan, "DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setattr(av_scan, "AV_LOG", str(tmp_path / "data" / "av.jsonl"))

    folder = _make_folder(tmp_path)
    sock = _FakeSocket(finding="Eicar-Test-Signature")
    monkeypatch.setattr(av_scan, "_client", lambda: sock)

    with pytest.raises(av_scan.Quarantined, match="Eicar"):
        av_scan.gate(folder)


def test_gate_file_quarantines_on_finding(monkeypatch, tmp_path):
    monkeypatch.delenv("CYBERSEC_SLM_ENFORCE_AV_SCAN", raising=False)
    monkeypatch.setattr(av_scan, "DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setattr(av_scan, "AV_LOG", str(tmp_path / "data" / "av.jsonl"))

    path = _write(tmp_path, "test.bin", b"fake malware content")
    sock = _FakeSocket(finding="Trojan.Generic")
    monkeypatch.setattr(av_scan, "_client", lambda: sock)

    with pytest.raises(av_scan.Quarantined, match="Trojan"):
        av_scan.gate_file(path)


# ───────────── clean files pass ──────────────────────────────────────────────

def test_gate_passes_clean_files(monkeypatch, tmp_path):
    monkeypatch.delenv("CYBERSEC_SLM_ENFORCE_AV_SCAN", raising=False)
    folder = _make_folder(tmp_path)

    sock = _FakeSocket(finding=None)
    monkeypatch.setattr(av_scan, "_client", lambda: sock)

    assert av_scan.gate(folder) is True


def test_gate_file_passes_clean_file(monkeypatch, tmp_path):
    monkeypatch.delenv("CYBERSEC_SLM_ENFORCE_AV_SCAN", raising=False)
    path = _write(tmp_path, "test.bin", b"clean content")

    sock = _FakeSocket(finding=None)
    monkeypatch.setattr(av_scan, "_client", lambda: sock)

    assert av_scan.gate_file(path) is True


# ─────────── multiple files: one bad taints the whole folder ─────────────────

def test_gate_quarantines_folder_on_any_bad_file(monkeypatch, tmp_path):
    """One malicious file in a folder should quarantine the whole folder."""
    monkeypatch.delenv("CYBERSEC_SLM_ENFORCE_AV_SCAN", raising=False)
    monkeypatch.setattr(av_scan, "DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setattr(av_scan, "AV_LOG", str(tmp_path / "data" / "av.jsonl"))

    folder = _make_folder(tmp_path, {
        "clean.txt": b"nothing wrong here",
        "evil.bin": b"definitely malware",
    })

    call_count = 0

    def _scan_alternating(sock, data):
        nonlocal call_count
        call_count += 1
        # Second file triggers a finding
        if call_count >= 2:
            return "Eicar-Test-Signature"
        return None

    sock = _FakeSocket(finding=None)
    monkeypatch.setattr(av_scan, "_client", lambda: sock)
    monkeypatch.setattr(av_scan, "_scan_stream", _scan_alternating)

    with pytest.raises(av_scan.Quarantined):
        av_scan.gate(folder)
