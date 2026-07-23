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
