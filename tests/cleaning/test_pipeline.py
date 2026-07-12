import json
import os

from cybersec_slm.cleaning import pipeline


def _write_jsonl(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def _read_all(root):
    text = ""
    for r, _d, fs in os.walk(root):
        for fn in fs:
            if fn.endswith(".jsonl"):
                with open(os.path.join(r, fn), encoding="utf-8") as f:
                    text += f.read()
    return text


def _redirect_outputs(monkeypatch, tmp_path):
    """Point every cleaning output + dedup sidecar at tmp so real dirs are untouched."""
    clean_dir = str(tmp_path / "clean_data")
    monkeypatch.setattr(pipeline, "OUT_CLEAN_DATA", clean_dir)
    monkeypatch.setattr(pipeline, "OUT_FLAGGED", str(tmp_path / "flagged"))
    monkeypatch.setattr(pipeline, "OUT_DROPPED", str(tmp_path / "dropped"))
    monkeypatch.setattr(pipeline, "REPORTS", str(tmp_path / "reports"))
    monkeypatch.setattr(pipeline, "DEDUP_CKPT", str(tmp_path / "dedup_ckpt.json"))
    monkeypatch.setattr(pipeline, "DEDUP_DONE", str(tmp_path / "dedup_done.json"))
    return clean_dir


def test_end_to_end(tmp_path, monkeypatch):
    """Drive the real production path: per-source clean (dedup disabled) then one
    cross-source final_global_dedup pass — the same steps the parallel worker runs."""
    corpus = tmp_path / "corpus"
    clean_en = ("The quick brown fox jumps over the lazy dog and then runs "
                "back to the den for a long rest in the afternoon today.")
    pii_en = ("Please contact the administrator at admin@example.com to get "
              "access to the secure internal system and the related logs.")
    distinct_en = ("Network security operations require constant monitoring of "
                   "the system logs and alerts for any suspicious activity now.")
    russian = ("Это длинный пример текста на русском языке предназначенный для "
               "проверки фильтрации языка в конвейере очистки данных проекта.")

    # Two sources; clean_en appears in BOTH (cross-source exact dup) plus twice in
    # s1 (intra-source exact dup). Per-source dedup is disabled, so final dedup is
    # what must catch all of them.
    _write_jsonl(str(corpus / "Test" / "s1" / "a.jsonl"), [
        {"source": "x", "url": "", "license": "", "text": clean_en},
        {"source": "x", "url": "", "license": "", "text": clean_en},   # exact dup
        {"source": "x", "url": "", "license": "", "text": "hi"},         # structural
        {"source": "x", "url": "", "license": "", "text": pii_en},       # pii
    ])
    _write_jsonl(str(corpus / "Test" / "s2" / "b.jsonl"), [
        {"source": "y", "url": "", "license": "", "text": russian},      # non-en
        {"source": "y", "url": "", "license": "", "text": distinct_en},
        {"source": "y", "url": "", "license": "", "text": clean_en},     # cross-src dup
    ])

    clean_dir = _redirect_outputs(monkeypatch, tmp_path)

    # Stub the translator so the test is deterministic and offline: it "translates"
    # any non-English record into a fixed English marker.
    marker = "TRANSLATED into english marker sentence for the pipeline test today."

    class _StubTranslator:
        backend = "stub"

        def translate(self, text, src=None):
            return marker, True

    monkeypatch.setattr(pipeline, "Translator", _StubTranslator)

    # 1) Per-source clean (mirrors worker.process_source -> clean_one_source).
    rows = []
    for src in ("s1", "s2"):
        rows += pipeline.clean_one_source(
            str(corpus / "Test" / src), raw_root=str(corpus), clean_data_dir=clean_dir)

    totals = {k: 0 for k in
              ("in", "out", "struct_dropped", "translated", "non_en_dropped",
               "pii_redacted")}
    for r in rows:
        for k in totals:
            totals[k] += r[k]

    assert totals["in"] == 7
    assert totals["struct_dropped"] >= 1
    # The Russian record is translated and kept, not dropped.
    assert totals["translated"] >= 1
    assert totals["non_en_dropped"] == 0
    assert totals["pii_redacted"] >= 1

    # 2) Cross-source final dedup (fresh pass). Six records reach dedup; the two
    # extra clean_en copies (intra-s1 + cross-source) are removed, leaving four.
    surviving_before = sum(1 for line in _read_all(clean_dir).splitlines() if line.strip())
    assert surviving_before == 6
    stats = pipeline.final_global_dedup(clean_dir)
    assert stats["exact_dups"] >= 2          # intra-s1 dup + cross-source dup
    assert stats["kept"] == 4
    # Checkpoint sidecars are written for resumability.
    assert os.path.exists(str(tmp_path / "dedup_ckpt.json"))
    assert os.path.exists(str(tmp_path / "dedup_done.json"))

    cleaned_text = _read_all(clean_dir)
    surviving_after = sum(1 for line in cleaned_text.splitlines() if line.strip())
    assert surviving_after == 4                         # two duplicate copies removed
    assert "admin@example.com" not in cleaned_text     # PII redacted
    assert marker in cleaned_text                       # translated, kept
    assert russian not in cleaned_text                  # original non-en gone


def test_drop_non_english_drops_instead_of_translating(tmp_path, monkeypatch):
    """With drop_non_english=True the non-English record is dropped and the
    translator is never consulted."""
    corpus = tmp_path / "corpus"
    russian = ("Это длинный пример текста на русском языке предназначенный для "
               "проверки фильтрации языка в конвейере очистки данных проекта.")
    english = ("Network security operations require constant monitoring of the "
               "system logs and alerts for any suspicious activity now today.")
    _write_jsonl(str(corpus / "Test" / "s1" / "a.jsonl"), [
        {"source": "x", "url": "", "license": "", "text": english},
        {"source": "x", "url": "", "license": "", "text": russian},
    ])
    clean_dir = _redirect_outputs(monkeypatch, tmp_path)
    pipeline.reset_cleaner_cache()

    class _BoomTranslator:
        backend = "stub"

        def translate(self, text, src=None):
            raise AssertionError("translator must not be called when dropping")

    monkeypatch.setattr(pipeline, "Translator", _BoomTranslator)

    rows = pipeline.clean_one_source(
        str(corpus / "Test" / "s1"), raw_root=str(corpus),
        clean_data_dir=clean_dir, drop_non_english=True)
    totals = {k: sum(r[k] for r in rows)
              for k in ("in", "translated", "non_en_dropped")}
    assert totals["in"] == 2
    assert totals["translated"] == 0
    assert totals["non_en_dropped"] == 1

    cleaned = _read_all(clean_dir)
    assert "Network security operations" in cleaned      # english kept
    assert russian not in cleaned                        # russian dropped
    assert "non-allowed language (dropped)" in _read_all(str(tmp_path / "dropped"))


def test_final_dedup_deterministic_first_wins(tmp_path, monkeypatch):
    """Sorted file order makes 'first duplicate wins' stable: the alphabetically
    first file keeps the record, the later file drops it."""
    clean_dir = _redirect_outputs(monkeypatch, tmp_path)
    dup = "identical cross source record used to prove deterministic dedup ordering"
    _write_jsonl(os.path.join(clean_dir, "Alpha", "a.jsonl"),
                 [{"text": dup}])
    _write_jsonl(os.path.join(clean_dir, "Beta", "b.jsonl"),
                 [{"text": dup}])

    stats = pipeline.final_global_dedup(clean_dir)
    assert stats["exact_dups"] == 1

    with open(os.path.join(clean_dir, "Alpha", "a.jsonl"), encoding="utf-8") as f:
        assert dup in f.read()                          # Alpha (first) kept
    with open(os.path.join(clean_dir, "Beta", "b.jsonl"), encoding="utf-8") as f:
        assert f.read().strip() == ""                   # Beta (later) dropped


def test_fresh_dedup_ignores_stale_checkpoint(tmp_path, monkeypatch):
    """A fresh (non-resume) pass must clear a prior build's checkpoint so surviving
    records are not wrongly flagged as duplicates on the next run."""
    clean_dir = _redirect_outputs(monkeypatch, tmp_path)
    rec = "a unique surviving record that should never be dropped as a duplicate here"
    path = os.path.join(clean_dir, "Dom", "s.jsonl")
    _write_jsonl(path, [{"text": rec}])

    # First fresh pass populates the checkpoint with rec's hash.
    pipeline.final_global_dedup(clean_dir)
    with open(path, encoding="utf-8") as f:
        assert rec in f.read()

    # Second fresh pass over the SAME (already-deduped) data must not treat rec as a
    # dup of the stale checkpoint — reset_dedup_state clears it first.
    stats = pipeline.final_global_dedup(clean_dir)
    assert stats["exact_dups"] == 0
    with open(path, encoding="utf-8") as f:
        assert rec in f.read()


def test_classify_runs_once_for_unchanged_records(tmp_path, monkeypatch):
    """The pre-sanitize anomaly classify (struct_fixed counter) must only run for
    records sanitize actually changed — unchanged records classify exactly once."""
    from cybersec_slm.cleaning import anomaly

    calls = {"n": 0}
    real_classify = anomaly.classify

    def counting_classify(rec):
        calls["n"] += 1
        return real_classify(rec)

    monkeypatch.setattr(anomaly, "classify", counting_classify)
    clean_dir = _redirect_outputs(monkeypatch, tmp_path)

    unchanged = ("A perfectly ordinary single spaced english sentence that the "
                 "sanitizer has no reason whatsoever to modify in any visible way.")
    dirty = ("A record whose text contains\r\nwindows line endings so the "
             "sanitizer rewrites it and marks the record as changed for us here.")
    corpus = tmp_path / "corpus"
    _write_jsonl(str(corpus / "Dom" / "s" / "f.jsonl"), [
        {"source": "x", "url": "", "license": "", "text": unchanged},
        {"source": "x", "url": "", "license": "", "text": dirty},
    ])

    rows = pipeline.clean_one_source(str(corpus / "Dom" / "s"),
                                     raw_root=str(corpus), clean_data_dir=clean_dir)
    assert rows and rows[0]["sanitized"] == 1
    # unchanged record: 1 classify; changed record: post-sanitize + pre-counter = 2.
    assert calls["n"] == 3
    pipeline.reset_cleaner_cache()


def test_cleaner_cache_builds_transformers_once(tmp_path, monkeypatch):
    """The stateless PII/lang/translate transformers are built once per process and
    reused across sources, not rebuilt for every clean_one_source call."""
    pipeline.reset_cleaner_cache()
    counts = {"redactor": 0, "langf": 0, "translator": 0}

    class _R:
        def __init__(self):
            counts["redactor"] += 1

        def redact(self, text):
            return text, 0

    class _L:
        def __init__(self):
            counts["langf"] += 1

        def detect(self, text):
            return "en"

        def lang_allowed(self, lang):
            return True

    class _T:
        backend = "stub"

        def __init__(self):
            counts["translator"] += 1

        def translate(self, text, src=None):
            return text, True

    monkeypatch.setattr(pipeline, "Redactor", _R)
    monkeypatch.setattr(pipeline, "LangFilter", _L)
    monkeypatch.setattr(pipeline, "Translator", _T)

    clean_dir = _redirect_outputs(monkeypatch, tmp_path)
    corpus = tmp_path / "corpus"
    body = ("A sufficiently long english sentence that survives the anomaly and "
            "structural checks without being dropped from the corpus today.")
    for src in ("s1", "s2"):
        _write_jsonl(str(corpus / "Dom" / src / "f.jsonl"),
                     [{"source": src, "url": "", "license": "", "text": body}])

    for src in ("s1", "s2"):
        pipeline.clean_one_source(str(corpus / "Dom" / src),
                                  raw_root=str(corpus), clean_data_dir=clean_dir)

    assert counts == {"redactor": 1, "langf": 1, "translator": 1}
    pipeline.reset_cleaner_cache()


def test_resume_dedup_skips_done_files(tmp_path, monkeypatch):
    """resume=True reloads the checkpoint, skips already-finished files, and still
    dedups a newly added file against the persisted exact-hash set."""
    clean_dir = _redirect_outputs(monkeypatch, tmp_path)
    rec = "shared record that a later resumed pass should recognize as a duplicate"
    first = os.path.join(clean_dir, "Alpha", "a.jsonl")
    _write_jsonl(first, [{"text": rec}])

    pipeline.final_global_dedup(clean_dir)              # fresh: Alpha finished + checkpointed

    # Add a new file containing an exact dup of the record already in Alpha.
    _write_jsonl(os.path.join(clean_dir, "Beta", "b.jsonl"), [{"text": rec}])
    stats = pipeline.final_global_dedup(clean_dir, resume=True)

    assert stats["skipped"] == 1                        # Alpha skipped (already done)
    assert stats["exact_dups"] == 1                     # Beta's dup caught via checkpoint
    with open(first, encoding="utf-8") as f:
        assert rec in f.read()                          # Alpha untouched
    with open(os.path.join(clean_dir, "Beta", "b.jsonl"), encoding="utf-8") as f:
        assert f.read().strip() == ""                   # Beta dup dropped
