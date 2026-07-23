import os

from cybersec_slm.cleaning.dedup import Deduper


def _base():
    return " ".join(f"word{i}" for i in range(100))


def _lines(path):
    with open(path, encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip()]


def test_exact_duplicate():
    d = Deduper(use_datasketch=False)
    is_dup1, _ = d.add("the same exact piece of text here")
    is_dup2, reason = d.add("the same exact piece of text here")
    assert not is_dup1
    assert is_dup2 and "exact" in reason


def test_exact_ignores_case_and_whitespace():
    d = Deduper(use_datasketch=False)
    d.add("Hello   World")
    is_dup, reason = d.add("hello world")
    assert is_dup and "exact" in reason


def test_near_duplicate():
    d = Deduper(use_datasketch=False)
    base = _base()
    d.add(base)
    near = base + " word100 word101 word102 word103 word104"   # ~95% shingle overlap
    is_dup, reason = d.add(near)
    assert is_dup and "near" in reason


def test_distinct_not_duplicate():
    d = Deduper(use_datasketch=False)
    d.add(_base())
    other = " ".join(f"alt{i}" for i in range(100))
    is_dup, _ = d.add(other)
    assert not is_dup


def test_checkpoint_round_trip(tmp_path):
    ckpt = str(tmp_path / "ckpt.txt")
    d = Deduper(use_datasketch=False, near=False)
    d.add("first record")
    d.add("second record")
    d.save_state(ckpt)

    d2 = Deduper(use_datasketch=False, near=False)
    d2.load_state(ckpt)
    is_dup, reason = d2.add("first record")
    assert is_dup and "exact" in reason
    assert not d2.add("a brand new record")[0]


def test_checkpoint_appends_only(tmp_path):
    """The journal must grow by what is new, not re-serialize the whole set:
    the old implementation sorted + rewrote every hash on each flush (1.42s and
    68 MB at 1M hashes, every 30s)."""
    ckpt = str(tmp_path / "ckpt.txt")
    d = Deduper(use_datasketch=False, near=False)
    d.add("one")
    d.save_state(ckpt)
    assert len(_lines(ckpt)) == 1
    first = _lines(ckpt)[0]

    d.add("two")
    d.save_state(ckpt)
    lines = _lines(ckpt)
    assert len(lines) == 2
    assert lines[0] == first              # earlier content untouched, not rewritten

    d.save_state(ckpt)                    # nothing new -> nothing appended
    assert len(_lines(ckpt)) == 2


def test_checkpoint_survives_a_torn_line(tmp_path):
    """A crash mid-append can leave a partial line; loading must skip it rather
    than poison the index."""
    ckpt = str(tmp_path / "ckpt.txt")
    d = Deduper(use_datasketch=False, near=False)
    d.add("durable record")
    d.save_state(ckpt)
    with open(ckpt, "a", encoding="utf-8") as f:
        f.write("deadbeef")               # torn: not 64 hex chars, no newline

    d2 = Deduper(use_datasketch=False, near=False)
    d2.load_state(ckpt)
    assert d2.add("durable record")[0]    # the good hash still loaded


def test_checkpoint_ignores_non_hex_junk(tmp_path):
    ckpt = str(tmp_path / "ckpt.txt")
    with open(ckpt, "w", encoding="utf-8") as f:
        f.write("not-a-hash\n" + "z" * 64 + "\n")
    d = Deduper(use_datasketch=False, near=False)
    d.load_state(ckpt)
    assert not d.add("anything")[0]       # nothing was trusted


def test_load_state_missing_file_is_noop(tmp_path):
    d = Deduper(use_datasketch=False, near=False)
    d.load_state(str(tmp_path / "nope.txt"))
    assert not d.add("x")[0]


def test_save_state_creates_parent_dir(tmp_path):
    ckpt = str(tmp_path / "nested" / "deep" / "ckpt.txt")
    d = Deduper(use_datasketch=False, near=False)
    d.add("rec")
    d.save_state(ckpt)
    assert os.path.exists(ckpt)


def test_exact_only_keeps_near():
    # near=False: byte-identical dupes are still removed, but fuzzy near-dups are
    # kept (the corpus policy that stops over-collapsing similar-but-distinct rows).
    d = Deduper(use_datasketch=False, near=False)
    assert d.backend == "exact-only"
    base = _base()
    d.add(base)
    near = base + " word100 word101 word102 word103 word104"   # ~95% overlap
    is_dup, _ = d.add(near)
    assert not is_dup                                           # near-dup NOT dropped
    is_dup2, reason = d.add(base)
    assert is_dup2 and "exact" in reason                       # exact STILL dropped

