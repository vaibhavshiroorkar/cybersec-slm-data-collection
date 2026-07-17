"""Reading the final dataset's real figures off disk.

The manifest only lands when a normalize run finishes, so every figure here has
to come from ``dataset.jsonl`` itself, including while a run is still appending
to it. No test needs a real corpus: each builds its own jsonl in tmp_path.
"""

import json

import pytest

from cybersec_slm.dashboard import final_stats


@pytest.fixture(autouse=True)
def _clean_memo():
    """The memo is module state; a leak between tests would hide double-counting."""
    final_stats.reset()
    yield
    final_stats.reset()


def _rec(source="alpha", tokens=10, **kw):
    return {"source": source, "token_count": tokens, "text": "x", **kw}


def _write(path, recs, *, mode="w", newline=True):
    body = "".join(json.dumps(r) + "\n" for r in recs)
    if not newline and body:
        body = body[:-1]
    with open(path, mode, encoding="utf-8") as f:
        f.write(body)
    return path


# ------------------------------------------------------------------ the bug ----
def test_a_dataset_with_no_manifest_still_reports_its_real_figures(tmp_path):
    """The bug: 825k records read as 0 because manifest.json had not been written."""
    p = _write(tmp_path / "dataset.jsonl", [
        _rec(source="alpha", tokens=10),
        _rec(source="beta", tokens=15),
        _rec(source="alpha", tokens=5),
    ])
    assert not (tmp_path / "manifest.json").exists()

    s = final_stats.scan(str(p))

    assert s.records == 3
    assert s.sources == 2           # alpha counted once, not twice
    assert s.tokens == 30
    assert s.size_mb > 0


def test_a_missing_dataset_is_all_zeros_not_a_crash(tmp_path):
    s = final_stats.scan(str(tmp_path / "nope.jsonl"))

    assert (s.records, s.sources, s.tokens, s.size_mb) == (0, 0, 0, 0.0)


def test_an_empty_dataset_is_all_zeros(tmp_path):
    p = _write(tmp_path / "dataset.jsonl", [])

    s = final_stats.scan(str(p))

    assert (s.records, s.sources, s.tokens) == (0, 0, 0)


# -------------------------------------------------------------- incremental ----
def test_appending_records_adds_only_the_new_ones(tmp_path):
    p = _write(tmp_path / "dataset.jsonl", [_rec(tokens=10)])
    assert final_stats.scan(str(p)).records == 1

    _write(p, [_rec(source="beta", tokens=7)], mode="a")
    s = final_stats.scan(str(p))

    assert s.records == 2
    assert s.tokens == 17
    assert s.sources == 2


def test_a_rescan_does_not_re_read_the_records_it_already_counted(tmp_path):
    """The whole point of the memo: a 5 GB corpus must not be re-parsed per tick."""
    p = _write(tmp_path / "dataset.jsonl", [_rec() for _ in range(50)])
    final_stats.scan(str(p))
    first_pass_end = final_stats._MEMO[str(p)].offset

    _write(p, [_rec()], mode="a")
    read = _bytes_read(lambda: final_stats.scan(str(p)))

    # Only the appended record's bytes are read, not the 50 already counted.
    assert read < first_pass_end
    assert final_stats.scan(str(p)).records == 51


def _bytes_read(fn):
    """Run fn and total the bytes it actually read off disk."""
    import builtins
    total = 0
    real_open = builtins.open

    class _Counting:
        def __init__(self, fh):
            self._fh = fh

        def __getattr__(self, name):
            return getattr(self._fh, name)

        def __enter__(self):
            self._fh.__enter__()
            return self

        def __exit__(self, *exc):
            return self._fh.__exit__(*exc)

        def read(self, *a):
            nonlocal total
            data = self._fh.read(*a)
            total += len(data)
            return data

    def _open(*a, **kw):
        return _Counting(real_open(*a, **kw))

    builtins.open = _open
    try:
        fn()
    finally:
        builtins.open = real_open
    return total


def test_scanning_twice_with_no_change_does_not_double_count(tmp_path):
    p = _write(tmp_path / "dataset.jsonl", [_rec(), _rec(source="beta")])

    first = final_stats.scan(str(p))
    second = final_stats.scan(str(p))

    assert (second.records, second.sources, second.tokens) == (
        first.records, first.sources, first.tokens)


# ------------------------------------------------- a writer mid-record ---------
def test_a_half_written_trailing_record_is_not_counted(tmp_path):
    """A live normalize run is appending; the last line may be incomplete."""
    p = _write(tmp_path / "dataset.jsonl", [_rec(tokens=10)])
    with open(p, "a", encoding="utf-8") as f:
        f.write('{"source": "beta", "token_c')       # torn mid-write

    s = final_stats.scan(str(p))

    assert s.records == 1           # the torn line is not a record yet
    assert s.tokens == 10


def test_a_torn_record_is_counted_once_it_is_completed(tmp_path):
    p = _write(tmp_path / "dataset.jsonl", [_rec(tokens=10)])
    with open(p, "a", encoding="utf-8") as f:
        f.write('{"source": "beta", "token_c')
    assert final_stats.scan(str(p)).records == 1

    with open(p, "a", encoding="utf-8") as f:      # the writer finishes the line
        f.write('ount": 7}\n')
    s = final_stats.scan(str(p))

    assert s.records == 2
    assert s.tokens == 17
    assert s.sources == 2


# ------------------------------------------------------ truncate and regrow ----
def test_a_truncated_dataset_resets_rather_than_appending_to_a_stale_count(tmp_path):
    """A --no-resume run rewrites dataset.jsonl from scratch."""
    p = _write(tmp_path / "dataset.jsonl", [_rec() for _ in range(10)])
    assert final_stats.scan(str(p)).records == 10

    _write(p, [_rec(source="gamma", tokens=3)], mode="w")     # truncate + regrow
    s = final_stats.scan(str(p))

    assert s.records == 1
    assert s.tokens == 3
    assert s.sources == 1


def test_a_regrow_past_the_old_offset_is_still_detected(tmp_path):
    """Size alone cannot catch this: the new file is longer than the old offset.

    The memo is only valid if the byte before its offset is still a newline, so a
    rewrite whose records land differently is caught rather than double-counted.
    """
    p = _write(tmp_path / "dataset.jsonl", [_rec(source="alpha", tokens=1)])
    final_stats.scan(str(p))

    # Rewrite with longer records, so the file is bigger than the previous offset
    # and the old offset now points into the middle of a line.
    _write(p, [_rec(source="beta", tokens=2, text="x" * 200) for _ in range(3)],
           mode="w")
    s = final_stats.scan(str(p))

    assert s.records == 3           # not 4
    assert s.sources == 1           # alpha is gone; it is not in this file
    assert s.tokens == 6


# -------------------------------------------------------------- robustness -----
def test_a_malformed_line_is_skipped_rather_than_killing_the_scan(tmp_path):
    p = tmp_path / "dataset.jsonl"
    with open(p, "w", encoding="utf-8") as f:
        f.write(json.dumps(_rec(tokens=10)) + "\n")
        f.write("{not json at all}\n")
        f.write(json.dumps(_rec(source="beta", tokens=5)) + "\n")

    s = final_stats.scan(str(p))

    assert s.records == 2
    assert s.tokens == 15


def test_records_missing_source_or_token_count_do_not_break_the_totals(tmp_path):
    p = tmp_path / "dataset.jsonl"
    with open(p, "w", encoding="utf-8") as f:
        f.write(json.dumps({"text": "no source, no tokens"}) + "\n")
        f.write(json.dumps(_rec(source="beta", tokens=5)) + "\n")

    s = final_stats.scan(str(p))

    assert s.records == 2
    assert s.tokens == 5
    assert s.sources == 2          # the sourceless record counts as its own "?"


def test_blank_lines_are_not_records(tmp_path):
    p = tmp_path / "dataset.jsonl"
    with open(p, "w", encoding="utf-8") as f:
        f.write(json.dumps(_rec()) + "\n\n")
        f.write(json.dumps(_rec(source="beta")) + "\n")

    assert final_stats.scan(str(p)).records == 2


def test_reset_forces_a_full_rescan(tmp_path):
    p = _write(tmp_path / "dataset.jsonl", [_rec()])
    final_stats.scan(str(p))

    final_stats.reset()

    assert str(p) not in final_stats._MEMO
    assert final_stats.scan(str(p)).records == 1
