from cybersec_slm.core import count_lines, sha256_file
from cybersec_slm.ingestion.common import IngestLog, category_of, group_key


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


def test_ingest_log_record_many(tmp_path):
    log = IngestLog(db=str(tmp_path / "ing.sqlite"))
    log.record_many([
        {"kind": "url", "name": "a", "domain": "D", "status": "ok"},
        {"kind": "pdf", "name": "b", "domain": "D", "status": "ok",
         "ts": "2020-01-01 00:00:00"},
    ])
    log.record_many([])                       # empty batch is a no-op, not an error

    df = log.table()
    assert len(df) == 2
    assert set(df["name"]) == {"a", "b"}
    # ts is preserved when supplied and auto-filled when omitted.
    assert (df.loc[df["name"] == "b", "ts"] == "2020-01-01 00:00:00").all()
    assert (df.loc[df["name"] == "a", "ts"].str.len() > 0).all()


def test_enrich_df_does_not_promote_a_payload_column_to_text():
    """`payload` is excluded from text derivation on purpose.

    cleaning/textmap.py deliberately omits `payload` so pure feature tables fall
    through to exclusion. Since textmap returns an existing `text` field unchanged,
    deriving text=payload at ingestion pre-empted that and let packet/malware blobs
    into the corpus as prose.
    """
    import pandas as pd

    from cybersec_slm.ingestion.common import enrich_df

    df = pd.DataFrame([{"payload": "QUJDREVG" * 20, "label": 1}])
    out = enrich_df(df, source="s", url="u", lic="MIT")
    assert "text" not in out.columns          # feature table stays text-less
    assert out.iloc[0]["source"] == "s"       # provenance is still stamped


def test_enrich_df_still_derives_text_from_a_real_prose_column():
    import pandas as pd

    from cybersec_slm.ingestion.common import enrich_df

    df = pd.DataFrame([{"body": "A readable paragraph of prose.", "label": 1}])
    out = enrich_df(df, source="s", url="u", lic="MIT")
    assert out.iloc[0]["text"] == "A readable paragraph of prose."
