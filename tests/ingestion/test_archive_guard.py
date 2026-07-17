"""Refusing archives that would exhaust the disk, and downloads that never end.

The bomb tests build real archives in tmp_path; nothing hits the network.
"""

import os
import zipfile

import pytest

from cybersec_slm.ingestion import archive


def _zip(path, entries):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, body in entries:
            z.writestr(name, body)
    return str(path)


# ------------------------------------------------------------ safe archives ---
def test_an_ordinary_archive_extracts(tmp_path):
    src = _zip(tmp_path / "ok.zip", [("a.csv", "col\n1\n"), ("d/b.csv", "col\n2\n")])
    out = tmp_path / "out"

    names = archive.safe_extract(src, str(out))

    assert sorted(os.path.basename(n) for n in names) == ["a.csv", "b.csv"]
    assert (out / "a.csv").read_text(encoding="utf-8") == "col\n1\n"


def test_an_empty_archive_is_not_an_error(tmp_path):
    src = _zip(tmp_path / "empty.zip", [])

    assert archive.safe_extract(src, str(tmp_path / "out")) == []


# ------------------------------------------------------------ zip bombs -------
def test_a_zip_bomb_is_refused_before_it_fills_the_disk(tmp_path):
    """The classic: a few KB on disk that expands to gigabytes. Nothing capped
    this, so a single catalog row could fill the volume."""
    src = _zip(tmp_path / "bomb.zip", [("big.csv", "0" * (80 * 1024 * 1024))])
    out = tmp_path / "out"

    with pytest.raises(archive.UnsafeArchive) as e:
        archive.safe_extract(src, str(out), max_total_bytes=8 * 1024 * 1024)

    assert "uncompressed" in str(e.value).lower()


def test_a_bomb_is_refused_without_writing_the_payload(tmp_path):
    """Refusing after writing 80MB is not refusing. The entries are read from the
    central directory, so the check happens before any byte is extracted."""
    src = _zip(tmp_path / "bomb.zip", [("big.csv", "0" * (80 * 1024 * 1024))])
    out = tmp_path / "out"

    with pytest.raises(archive.UnsafeArchive):
        archive.safe_extract(src, str(out), max_total_bytes=8 * 1024 * 1024)

    written = sum(f.stat().st_size for f in out.rglob("*") if f.is_file()) \
        if out.exists() else 0
    assert written == 0


def test_too_many_entries_is_refused(tmp_path):
    src = _zip(tmp_path / "many.zip", [(f"f{i}.csv", "x") for i in range(50)])

    with pytest.raises(archive.UnsafeArchive) as e:
        archive.safe_extract(src, str(tmp_path / "out"), max_entries=10)

    assert "entries" in str(e.value).lower()


def test_an_absurd_compression_ratio_is_refused(tmp_path):
    """Catches a bomb that slips under the byte cap but is still obviously one."""
    src = _zip(tmp_path / "ratio.zip", [("big.csv", "0" * (20 * 1024 * 1024))])

    with pytest.raises(archive.UnsafeArchive) as e:
        archive.safe_extract(src, str(tmp_path / "out"),
                             max_total_bytes=1 << 30, max_ratio=50)

    assert "ratio" in str(e.value).lower()


def test_a_traversal_entry_is_refused(tmp_path):
    """CPython's extractall strips these, but safe_extract writes entries itself,
    so it has to make the guarantee rather than inherit it."""
    src = tmp_path / "trav.zip"
    with zipfile.ZipFile(src, "w") as z:
        z.writestr("../escape.csv", "col\n1\n")

    with pytest.raises(archive.UnsafeArchive) as e:
        archive.safe_extract(str(src), str(tmp_path / "out"))

    assert "path" in str(e.value).lower() or "traversal" in str(e.value).lower()


def test_an_absolute_path_entry_is_refused(tmp_path):
    src = tmp_path / "abs.zip"
    with zipfile.ZipFile(src, "w") as z:
        z.writestr("/etc/passwd", "root:x:0:0\n")

    with pytest.raises(archive.UnsafeArchive):
        archive.safe_extract(str(src), str(tmp_path / "out"))


def test_a_corrupt_archive_is_refused_rather_than_raising_zipfile_internals(tmp_path):
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"PK\x03\x04 not really a zip")

    with pytest.raises(archive.UnsafeArchive):
        archive.safe_extract(str(bad), str(tmp_path / "out"))


# ------------------------------------------------------- the download cap -----
class _Stream:
    """An httpx-shaped streaming response yielding `n` bytes."""

    def __init__(self, url, n):
        self.url = url
        self.status_code = 200
        self.headers = {}
        self.is_redirect = False
        self._n = n

    def raise_for_status(self):
        return None

    def iter_bytes(self, chunk=None):
        sent = 0
        while sent < self._n:
            step = min(1 << 16, self._n - sent)
            sent += step
            yield b"0" * step

    def close(self):
        return None


def _fake_stream(monkeypatch, n):
    from cybersec_slm.ingestion import common, urlscreen

    monkeypatch.setattr(urlscreen, "_resolve", lambda h: ["93.184.216.34"])
    monkeypatch.setattr(common, "_screened_hops",
                        lambda url, t, opener: _Stream(url, n))
    return common


def test_a_download_under_the_cap_is_written(tmp_path, monkeypatch):
    common = _fake_stream(monkeypatch, 1 << 17)
    dest = str(tmp_path / "ok.bin")

    size, digest = common.download("https://example.test/x", dest)

    assert size == 1 << 17
    assert os.path.getsize(dest) == 1 << 17
    assert len(digest) == 64


def test_a_download_past_the_cap_aborts(tmp_path, monkeypatch):
    """--max-source-gb screens the catalog's *declared* size, which a wrong or
    hostile row simply lies about. This counts the bytes actually arriving."""
    common = _fake_stream(monkeypatch, 4 << 20)
    monkeypatch.setenv("CYBERSEC_SLM_MAX_DOWNLOAD_BYTES", str(1 << 20))

    with pytest.raises(common.DownloadTooLarge):
        common.download("https://example.test/big", str(tmp_path / "big.bin"))


def test_an_aborted_download_leaves_no_partial_file(tmp_path, monkeypatch):
    """A truncated file left on disk would be read as a real, valid source."""
    common = _fake_stream(monkeypatch, 4 << 20)
    monkeypatch.setenv("CYBERSEC_SLM_MAX_DOWNLOAD_BYTES", str(1 << 20))
    dest = str(tmp_path / "big.bin")

    with pytest.raises(common.DownloadTooLarge):
        common.download("https://example.test/big", dest)

    assert not os.path.exists(dest)
