"""tools/purge_translated.py: strip machine-translated records from data/clean."""

import importlib.util
import json
import os

_TOOL = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "tools", "purge_translated.py")
_spec = importlib.util.spec_from_file_location("purge_translated", _TOOL)
purge = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(purge)


def _write(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def _read(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(ln) for ln in f if ln.strip()]


def _corpus(tmp_path):
    clean = tmp_path / "clean"
    _write(str(clean / "Dom" / "src" / "a.jsonl"), [
        {"text": "an english record that was never touched by the translator"},
        {"text": "translated into english", "_orig_lang": "ru"},
        {"text": "another plain english record kept as it was cleaned"},
        {"text": "also translated", "_orig_lang": "de"},
    ])
    _write(str(clean / "Dom" / "other" / "b.jsonl"), [
        {"text": "no translated records live in this file at all"},
    ])
    return clean


def test_find_files_only_returns_files_holding_translated_records(tmp_path):
    clean = _corpus(tmp_path)
    found = purge.find_files(str(clean))
    assert [os.path.basename(p) for p in found] == ["a.jsonl"]      # not b.jsonl


def test_report_only_by_default(tmp_path):
    clean = _corpus(tmp_path)
    path = str(clean / "Dom" / "src" / "a.jsonl")
    kept, purged = purge.purge_file(path, clean_root=str(clean),
                                    dropped_root=str(tmp_path / "dropped"))
    assert (kept, purged) == (2, 2)
    assert len(_read(path)) == 4                                    # untouched
    assert not (tmp_path / "dropped").exists()


def test_apply_strips_translated_and_annotates_them_into_dropped(tmp_path):
    clean = _corpus(tmp_path)
    path = str(clean / "Dom" / "src" / "a.jsonl")
    kept, purged = purge.purge_file(path, clean_root=str(clean),
                                    dropped_root=str(tmp_path / "dropped"),
                                    apply=True)
    assert (kept, purged) == (2, 2)

    remaining = _read(path)
    assert len(remaining) == 2
    assert all("_orig_lang" not in r for r in remaining)

    dropped = _read(str(tmp_path / "dropped" / "Dom" / "src" / "a.jsonl"))
    assert len(dropped) == 2
    assert {r["_orig_lang"] for r in dropped} == {"ru", "de"}       # recoverable
    assert all(r["_stage"] == "langfilter" for r in dropped)
    assert all(purge.REASON in r["_reason"] for r in dropped)


def test_apply_is_idempotent(tmp_path):
    """A second pass finds nothing left and must not re-drop anything."""
    clean = _corpus(tmp_path)
    path = str(clean / "Dom" / "src" / "a.jsonl")
    kw = {"clean_root": str(clean), "dropped_root": str(tmp_path / "dropped"),
          "apply": True}
    purge.purge_file(path, **kw)
    kept, purged = purge.purge_file(path, **kw)
    assert (kept, purged) == (2, 0)
    assert len(_read(str(tmp_path / "dropped" / "Dom" / "src" / "a.jsonl"))) == 2
