import json
import os

from cybersec_slm.cleaning import pipeline


def _write_jsonl(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def test_end_to_end(tmp_path, monkeypatch):
    corpus = tmp_path / "corpus"
    clean_en = ("The quick brown fox jumps over the lazy dog and then runs "
                "back to the den for a long rest in the afternoon today.")
    pii_en = ("Please contact the administrator at admin@example.com to get "
              "access to the secure internal system and the related logs.")
    distinct_en = ("Network security operations require constant monitoring of "
                   "the system logs and alerts for any suspicious activity now.")
    russian = ("Это длинный пример текста на русском языке предназначенный для "
               "проверки фильтрации языка в конвейере очистки данных проекта.")

    _write_jsonl(str(corpus / "Test" / "s1" / "a.jsonl"), [
        {"source": "x", "url": "", "license": "", "text": clean_en},
        {"source": "x", "url": "", "license": "", "text": clean_en},   # exact dup
        {"source": "x", "url": "", "license": "", "text": "hi"},         # structural
        {"source": "x", "url": "", "license": "", "text": pii_en},       # pii
    ])
    _write_jsonl(str(corpus / "Test" / "s2" / "b.jsonl"), [
        {"source": "y", "url": "", "license": "", "text": russian},      # non-en
        {"source": "y", "url": "", "license": "", "text": distinct_en},
    ])

    # redirect all outputs into tmp so the real folders are untouched
    monkeypatch.setattr(pipeline, "OUT_CLEAN_DATA", str(tmp_path / "clean_data"))
    monkeypatch.setattr(pipeline, "OUT_FLAGGED", str(tmp_path / "flagged"))
    monkeypatch.setattr(pipeline, "OUT_DROPPED", str(tmp_path / "dropped"))
    monkeypatch.setattr(pipeline, "REPORTS", str(tmp_path / "reports"))
    # isolate the dedup checkpoint: run_all resumes from it by default, so without
    # this the test would pollute (and then re-read) the real logs/ checkpoint and
    # flag its own records as exact dups on a second run.
    monkeypatch.setattr(pipeline, "DEDUP_CKPT", str(tmp_path / "dedup_ckpt"))

    # Stub the translator so the test is deterministic and offline: it "translates"
    # any non-English record into a fixed English marker.
    marker = "TRANSLATED into english marker sentence for the pipeline test today."

    class _StubTranslator:
        backend = "stub"

        def translate(self, text, src=None):
            return marker, True

    monkeypatch.setattr(pipeline, "Translator", _StubTranslator)

    rows = pipeline.run_all(input_dir=str(corpus))

    totals = {k: 0 for k in
              ("in", "out", "struct_dropped", "exact_dups", "translated",
               "non_en_dropped", "pii_redacted")}
    for r in rows:
        for k in totals:
            totals[k] += r[k]

    assert totals["in"] == 6
    assert totals["exact_dups"] >= 1
    assert totals["struct_dropped"] >= 1
    # The Russian record is translated and kept, not dropped.
    assert totals["translated"] >= 1
    assert totals["non_en_dropped"] == 0
    assert totals["pii_redacted"] >= 1
    assert totals["out"] >= 4
    assert os.path.exists(str(tmp_path / "reports" / "clean_report.csv"))

    # cleaned output must not contain the redacted email, must contain the
    # translated marker, and must not contain the original Russian text.
    cleaned_text = ""
    for r, _d, fs in os.walk(str(tmp_path / "clean_data")):
        for fn in fs:
            with open(os.path.join(r, fn), encoding="utf-8") as f:
                cleaned_text += f.read()
    assert "admin@example.com" not in cleaned_text
    assert marker in cleaned_text
    assert russian not in cleaned_text
