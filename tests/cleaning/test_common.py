"""The cleaning input walker: what counts as corpus under data/raw."""

from cybersec_slm.cleaning.common import find_input_files


def test_find_input_files_skips_extraction_scratch(tmp_path):
    """``_z`` extraction scratch is never walked into.

    ``fetch_url`` unzips an archive into ``<source>/_z``, combines the payload
    into one top-level ``<source>.jsonl``, then deletes ``_z`` — a delete that
    fails silently on Windows (read-only entries / long paths) and can strand
    millions of files. Those files are *pre-combine intermediates*, so descending
    into them is both wasted work (a full raw walk cost minutes) and a
    duplicate-data risk: their records are already in the combined .jsonl.
    """
    raw = tmp_path / "raw"
    src = raw / "Dom" / "src"
    (src / "_z" / "nested").mkdir(parents=True)
    (src / "data.jsonl").write_text('{"text": "corpus"}\n', encoding="utf-8")
    # Intermediates stranded inside the scratch dir; already folded into data.jsonl.
    (src / "_z" / "part-000.jsonl").write_text('{"text": "dup"}\n', encoding="utf-8")
    (src / "_z" / "nested" / "part-001.jsonl").write_text('{"text": "dup"}\n',
                                                          encoding="utf-8")

    found = sorted(rel for _ap, _sub, _source, rel in find_input_files(str(raw)))
    assert found == ["Dom/src/data.jsonl"]


def test_find_input_files_maps_domain_and_source(tmp_path):
    """Layout data/raw/<Sub-Domain>/<source>/<file>.jsonl maps to (sub, source, rel)."""
    raw = tmp_path / "raw"
    (raw / "Cryptography" / "acme").mkdir(parents=True)
    (raw / "Cryptography" / "acme" / "a.jsonl").write_text("{}\n", encoding="utf-8")

    (_ap, sub, source, rel), = list(find_input_files(str(raw)))
    assert (sub, source, rel) == ("Cryptography", "acme", "Cryptography/acme/a.jsonl")


def test_atomic_replace_retries_transient_permission_error(tmp_path, monkeypatch):
    """A Windows-style transient lock (PermissionError) on the first attempt is
    retried and succeeds, instead of aborting the caller (e.g. final_global_dedup)
    mid-pass. This is the retry sourcing/sheet.py already had; cleaning now shares it."""
    from cybersec_slm import core

    src = tmp_path / "a.tmp"
    dst = tmp_path / "a"
    src.write_text("payload", encoding="utf-8")

    real_replace = core.os.replace
    calls = {"n": 0}

    def _flaky(s, d):
        calls["n"] += 1
        if calls["n"] == 1:
            raise PermissionError("file is locked by another process")
        return real_replace(s, d)

    monkeypatch.setattr(core.os, "replace", _flaky)
    monkeypatch.setattr(core.time, "sleep", lambda *_a, **_k: None)   # no real delay

    core.atomic_replace(str(src), str(dst))

    assert calls["n"] == 2                       # failed once, retried, succeeded
    assert dst.read_text(encoding="utf-8") == "payload"
    assert not src.exists()


def test_atomic_replace_reraises_persistent_permission_error(tmp_path, monkeypatch):
    import pytest

    from cybersec_slm import core
    src = tmp_path / "a.tmp"
    src.write_text("x", encoding="utf-8")

    monkeypatch.setattr(core.os, "replace",
                        lambda *_a, **_k: (_ for _ in ()).throw(PermissionError("locked")))
    monkeypatch.setattr(core.time, "sleep", lambda *_a, **_k: None)

    with pytest.raises(PermissionError):
        core.atomic_replace(str(src), str(tmp_path / "a"), retries=3)
