from cybersec_slm.core import count_lines, sha256_file
from cybersec_slm.ingestion.common import category_of, group_key


def test_category_of():
    assert category_of("hf") == "Dataset"
    assert category_of("kaggle") == "Dataset"
    assert category_of("github") == "Repo"
    assert category_of("pdf") == "Document"
    assert category_of("feed") == "Feed"
    assert category_of("website") == "Website"
    assert category_of("mystery") == "Mystery"     # title-cased fallback


def test_group_key_strips_shards_and_data_prefix():
    assert group_key("data/train-00000-of-00002.parquet") == "train"
    assert group_key("cve_data/train-00001-of-1.jsonl") == "cve_data_train"
    assert group_key("plain.csv") == "plain"


def test_count_lines(tmp_path):
    p = tmp_path / "x.jsonl"
    p.write_text("a\nb\nc\n", encoding="utf-8")
    assert count_lines(str(p)) == 3


def test_sha256_file_is_stable(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"hello")
    assert sha256_file(str(p)) == (
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
