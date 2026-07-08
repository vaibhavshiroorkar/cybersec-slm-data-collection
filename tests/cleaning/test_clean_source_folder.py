"""clean_source_folder cleans one source folder, dedup disabled, O(files)."""
import json
import os

from cybersec_slm.cleaning import pipeline


class _StubRedactor:
    def redact(self, text):
        return text, 0


class _StubLang:
    def detect(self, text):
        return "en"

    def lang_allowed(self, lang):
        return True


class _StubTranslator:
    def translate(self, text, src=None):
        return text, True


def _write_jsonl(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def test_cleans_only_its_own_folder_and_mirrors_layout(tmp_path):
    raw = tmp_path / "raw"
    clean = tmp_path / "clean"
    # target source — text must clear MIN_TEXT_CHARS (50) to survive the
    # anomaly gate; two distinct records so both are kept.
    _write_jsonl(str(raw / "Malware" / "srcA" / "a.jsonl"),
                 [{"text": "This is the first malware analysis record with plenty "
                           "of descriptive prose to pass the anomaly gate."},
                  {"text": "This is the second and entirely different record, also "
                           "long enough to be kept by the cleaning pipeline."}])
    # a DIFFERENT source that must be left untouched
    _write_jsonl(str(raw / "Network" / "srcB" / "b.jsonl"),
                 [{"text": "A network security record that should never be touched "
                           "because clean_source_folder scans only srcA's folder."}])

    rows = pipeline.clean_source_folder(
        str(raw / "Malware" / "srcA"),
        redactor=_StubRedactor(), langf=_StubLang(), translator=_StubTranslator(),
        raw_root=str(raw), clean_data_dir=str(clean),
        flagged_dir=str(tmp_path / "flagged"), dropped_dir=str(tmp_path / "dropped"))

    # output mirrors the data/raw layout under clean/
    out = clean / "Malware" / "srcA" / "a.jsonl"
    assert out.exists()
    assert out.read_text(encoding="utf-8").count("\n") == 2
    # srcB was never cleaned (folder scan is scoped)
    assert not (clean / "Network").exists()
    assert rows and rows[0]["file"] == "Malware/srcA/a.jsonl"
    assert rows[0]["out"] == 2
