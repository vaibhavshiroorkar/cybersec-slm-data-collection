from cybersec_slm.cleaning.dedup import Deduper


def _base():
    return " ".join(f"word{i}" for i in range(100))


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
