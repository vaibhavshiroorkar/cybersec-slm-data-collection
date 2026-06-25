from cybersec_slm.cleaning.translate import Translator, _chunk, _normalize_code


def test_normalize_code():
    assert _normalize_code("__label__de") == "de"
    assert _normalize_code("zh-cn") == "zh"
    assert _normalize_code("EN") == "en"
    assert _normalize_code(None) is None
    assert _normalize_code("unknown") is None
    assert _normalize_code("non-latin") is None


def test_chunk_short_text_is_single_piece():
    assert _chunk("hello world") == ["hello world"]


def test_chunk_splits_on_paragraphs_under_limit():
    paras = ["a" * 3000, "b" * 3000, "c" * 3000]
    text = "\n\n".join(paras)
    chunks = _chunk(text, limit=4500)
    assert len(chunks) > 1
    assert all(len(c) <= 4500 for c in chunks)


def test_chunk_hard_slices_oversized_paragraph():
    text = "x" * 10000
    chunks = _chunk(text, limit=4500)
    assert all(len(c) <= 4500 for c in chunks)
    assert "".join(chunks) == text


def test_no_backend_is_a_noop():
    # Forcing an unavailable backend keeps the translator inert; translate()
    # returns the original text with ok=False so callers fall back to dropping.
    tr = Translator(backend="none")
    assert tr.available is False
    out, ok = tr.translate("bonjour le monde", src="fr")
    assert out == "bonjour le monde"
    assert ok is False


def test_empty_text_is_not_translated():
    tr = Translator(backend="none")
    out, ok = tr.translate("", src="fr")
    assert ok is False
