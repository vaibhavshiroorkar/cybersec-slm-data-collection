"""Seeing the executables an archive shipped, instead of silently deleting them.

Ingestion keeps only EXT_PRIORITY files out of an extracted archive; everything
else was dropped with no log line and no ledger entry, then rmtree'd. A repo
could ship a malicious binary and the pipeline reported nothing. Nothing is
executed either way; the gap is that nothing was ever *reported*.
"""

import os

from cybersec_slm.ingestion import binscan


def _write(tmp_path, name, body: bytes):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body)
    return str(p)


# ------------------------------------------------------------------ sniff -----
def test_a_windows_executable_is_recognized(tmp_path):
    p = _write(tmp_path, "tool.exe", b"MZ\x90\x00" + b"\x00" * 128)

    assert binscan.sniff(p) == "pe"


def test_a_linux_executable_is_recognized(tmp_path):
    p = _write(tmp_path, "tool", b"\x7fELF\x02\x01\x01" + b"\x00" * 128)

    assert binscan.sniff(p) == "elf"


def test_a_mach_o_executable_is_recognized(tmp_path):
    p = _write(tmp_path, "tool", b"\xcf\xfa\xed\xfe" + b"\x00" * 128)

    assert binscan.sniff(p) == "macho"


def test_an_office_document_is_recognized(tmp_path):
    """OLE is how macro malware still travels."""
    p = _write(tmp_path, "sheet.xls", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64)

    assert binscan.sniff(p) == "ole"


def test_a_nested_archive_is_recognized(tmp_path):
    p = _write(tmp_path, "inner.zip", b"PK\x03\x04" + b"\x00" * 64)

    assert binscan.sniff(p) == "zip"


def test_an_ordinary_data_file_is_not_flagged(tmp_path):
    p = _write(tmp_path, "data.csv", b"col,val\n1,2\n")

    assert binscan.sniff(p) == ""


def test_an_empty_or_missing_file_is_not_flagged(tmp_path):
    assert binscan.sniff(_write(tmp_path, "empty.bin", b"")) == ""
    assert binscan.sniff(str(tmp_path / "nope.bin")) == ""


def test_the_extension_does_not_decide(tmp_path):
    """A .csv that is really a PE is exactly the case a name-based check misses."""
    p = _write(tmp_path, "innocent.csv", b"MZ\x90\x00" + b"\x00" * 128)

    assert binscan.sniff(p) == "pe"


# ------------------------------------------------------------- scan_tree ------
def test_scan_tree_reports_every_executable_it_finds(tmp_path):
    root = tmp_path / "z"
    _write(root, "data.csv", b"col\n1\n")
    _write(root, "bin/tool.exe", b"MZ\x90\x00" + b"\x00" * 64)
    _write(root, "lib/thing.so", b"\x7fELF\x02" + b"\x00" * 64)

    found = binscan.scan_tree(str(root))

    assert {f["kind"] for f in found} == {"pe", "elf"}
    assert {os.path.basename(f["path"]) for f in found} == {"tool.exe", "thing.so"}
    assert all(f["size"] > 0 for f in found)


def test_scan_tree_is_quiet_for_a_clean_archive(tmp_path):
    root = tmp_path / "z"
    _write(root, "a.csv", b"col\n1\n")
    _write(root, "b/c.json", b'{"a": 1}')

    assert binscan.scan_tree(str(root)) == []


def test_scan_tree_paths_are_relative_to_the_archive(tmp_path):
    """The absolute temp path is noise; the operator needs the path inside the zip."""
    root = tmp_path / "z"
    _write(root, "bin/tool.exe", b"MZ\x90\x00" + b"\x00" * 64)

    [found] = binscan.scan_tree(str(root))

    assert found["path"] == "bin/tool.exe"


def test_scan_tree_of_a_missing_directory_is_empty(tmp_path):
    assert binscan.scan_tree(str(tmp_path / "nope")) == []


def test_scan_tree_caps_what_it_reports(tmp_path):
    """A repo of 10,000 binaries is one finding to act on, not 10,000 log lines."""
    root = tmp_path / "z"
    for i in range(30):
        _write(root, f"b{i}.exe", b"MZ\x90\x00" + b"\x00" * 8)

    found = binscan.scan_tree(str(root), max_report=5)

    assert len(found) == 5


def test_scan_tree_reports_the_true_total_even_when_capped(tmp_path):
    root = tmp_path / "z"
    for i in range(30):
        _write(root, f"b{i}.exe", b"MZ\x90\x00" + b"\x00" * 8)

    assert binscan.count_binaries(str(root)) == 30


# ------------------------------------------------------------- report ---------
def test_report_records_a_source_that_ships_binaries(tmp_path, monkeypatch):
    monkeypatch.setattr(binscan, "LOGS", str(tmp_path / "logs"))
    root = tmp_path / "z"
    _write(root, "data.csv", b"col\n1\n")
    _write(root, "bin/tool.exe", b"MZ\x90\x00" + b"\x00" * 64)

    entry = binscan.report(str(root), source="evil-repo", url="https://x/y",
                           domain="Threat Intelligence")

    assert entry["source"] == "evil-repo"
    assert entry["total"] == 1
    assert entry["by_kind"] == {"pe": 1}
    assert binscan.findings(binscan.report_path()) == [entry]


def test_report_says_nothing_for_a_clean_source(tmp_path, monkeypatch):
    monkeypatch.setattr(binscan, "LOGS", str(tmp_path / "logs"))
    root = tmp_path / "z"
    _write(root, "data.csv", b"col\n1\n")

    assert binscan.report(str(root), source="clean") is None
    assert binscan.findings(binscan.report_path()) == []


def test_report_states_the_true_total_when_the_list_is_capped(tmp_path, monkeypatch):
    """'20 of 4,312' is a very different fact from '20'."""
    monkeypatch.setattr(binscan, "LOGS", str(tmp_path / "logs"))
    root = tmp_path / "z"
    for i in range(30):
        _write(root, f"b{i}.exe", b"MZ\x90\x00" + b"\x00" * 8)

    entry = binscan.report(str(root), source="many")

    assert entry["total"] == 30
    assert entry["shown"] == binscan.DEFAULT_MAX_REPORT


def test_report_never_fails_the_fetch(tmp_path, monkeypatch):
    """A source shipping a binary is worth knowing; failing to write the note is
    not worth losing the fetch over."""
    monkeypatch.setattr(binscan, "LOGS", str(tmp_path / "logs"))
    monkeypatch.setattr(binscan, "scan_tree",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("boom")))
    root = tmp_path / "z"
    _write(root, "bin/tool.exe", b"MZ\x90\x00" + b"\x00" * 64)

    assert binscan.report(str(root), source="x") is None


def test_findings_of_a_missing_report_is_empty(tmp_path):
    assert binscan.findings(str(tmp_path / "nope.jsonl")) == []
