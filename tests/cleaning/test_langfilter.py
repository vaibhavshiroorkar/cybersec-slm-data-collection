from cybersec_slm.cleaning import langfilter as _langfilter
from cybersec_slm.cleaning.langfilter import LangFilter


def _warnings_during(fn):
    """Run `fn`, returning the WARNING lines it logged.

    The pipeline logs through loguru, which does not propagate to pytest's caplog,
    so capture with a loguru sink instead.
    """
    msgs: list[str] = []
    sink = _langfilter.logger.add(lambda m: msgs.append(str(m)), level="WARNING")
    try:
        return fn(), msgs
    finally:
        _langfilter.logger.remove(sink)


def test_missing_fasttext_model_warns_loudly(monkeypatch):
    """A missing model silently costs ~265x per record, and accuracy.

    The file is gitignored on purpose, so a fresh checkout lands on langdetect
    with nothing but a DEBUG line to say so - which is how a pipeline ends up
    spending 17-43% of its clean cost on language ID without anyone noticing.
    """
    monkeypatch.setattr(_langfilter, "_find_fasttext_model", lambda: None)
    lf, msgs = _warnings_during(LangFilter)
    if lf.backend == "langdetect":                 # only when langdetect is present
        assert any("lid.176.ftz" in m and "slower" in m for m in msgs)


def test_no_warning_when_a_backend_is_explicitly_chosen(monkeypatch):
    """Asking for langdetect by name is a choice, not an accident."""
    monkeypatch.setattr(_langfilter, "_find_fasttext_model", lambda: None)
    _lf, msgs = _warnings_during(lambda: LangFilter(backend="langdetect"))
    assert not any("lid.176.ftz" in m for m in msgs)


def test_english_is_allowed():
    lf = LangFilter(backend="heuristic")
    text = ("The system processes the data and stores it in the database "
            "for analysis and reporting to the team every day.")
    assert lf.detect(text) == "en"
    assert lf.is_allowed(text)


def test_non_latin_is_dropped():
    lf = LangFilter(backend="heuristic")
    ru = ("Это пример текста на русском языке для проверки определения "
          "языка системой очистки данных и фильтрации.")
    assert not lf.is_allowed(ru)


def test_uncertain_is_kept():
    lf = LangFilter(backend="heuristic")
    # too little signal to decide -> conservative keep
    assert lf.is_allowed("OK")
