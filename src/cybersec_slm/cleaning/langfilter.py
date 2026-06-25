#!/usr/bin/env python3
"""Language filtering — keep only allowed languages (default English).

Backends, in preference order:
  1. fastText lid.176  (needs `fasttext` + a model file lid.176.ftz/.bin)
  2. langdetect
  3. stdlib heuristic   (script ranges + English stopword hits)

Conservative drop policy: a record is dropped only on a *confident* non-allowed
detection. Unknown/uncertain results are kept, so the fallback never throws away
text it simply failed to identify.

Public API:
    lf = LangFilter()
    lang = lf.detect(text)
    keep = lf.is_allowed(text)     # True unless confidently non-allowed
"""

from __future__ import annotations

import os
import re

from .common import LANGS, PKG_DIR, logger, try_import

_STOPWORDS = {"the", "and", "of", "to", "in", "is", "for", "that", "with",
              "as", "are", "on", "be", "this", "by", "an", "or", "it", "from"}
_LATIN_RE = re.compile(r"[A-Za-z]")
_WORD_RE = re.compile(r"[A-Za-z]+")

# Unicode script blocks that are clearly not English.
_NONLATIN_RE = re.compile(
    r"[Ѐ-ӿ؀-ۿऀ-ॿ぀-ヿ"
    r"一-鿿가-힯֐-׿]")


def _find_fasttext_model() -> str | None:
    for name in ("lid.176.ftz", "lid.176.bin"):
        p = os.path.join(PKG_DIR, name)
        if os.path.exists(p):
            return p
    env = os.environ.get("FASTTEXT_LID_MODEL")
    return env if env and os.path.exists(env) else None


def _heuristic(text: str) -> str:
    sample = text[:2000]
    if not sample.strip():
        return "unknown"
    nonlatin = len(_NONLATIN_RE.findall(sample))
    latin = len(_LATIN_RE.findall(sample))
    if nonlatin > latin and nonlatin > 10:
        return "non-latin"            # confidently not English
    words = [w.lower() for w in _WORD_RE.findall(sample)]
    if len(words) >= 10:
        hits = sum(1 for w in words if w in _STOPWORDS)
        if hits / len(words) >= 0.05:
            return "en"
    return "unknown"


class LangFilter:
    def __init__(self, backend="auto"):
        self.backend = "heuristic"
        self._model = None
        self._langdetect = None

        if backend in ("auto", "fasttext"):
            ft = try_import("fasttext")
            model_path = _find_fasttext_model()
            if ft is not None and model_path:
                try:
                    self._model = ft.load_model(model_path)
                    self.backend = "fasttext"
                except Exception as ex:
                    logger.warning(f"lang: fasttext load failed ({type(ex).__name__})")
        if self.backend == "heuristic" and backend in ("auto", "langdetect"):
            ld = try_import("langdetect")
            if ld is not None:
                self._langdetect = ld
                self.backend = "langdetect"
        logger.debug(f"lang: backend = {self.backend}")

    def detect(self, text: str) -> str:
        sample = (text or "")[:2000].replace("\n", " ").strip()
        if not sample:
            return "unknown"
        if self.backend == "fasttext":
            try:
                label = self._model.predict(sample)[0][0]   # '__label__en'
                return label.replace("__label__", "")
            except Exception:
                return "unknown"
        if self.backend == "langdetect":
            try:
                return self._langdetect.detect(sample)
            except Exception:
                return "unknown"
        return _heuristic(sample)

    def lang_allowed(self, lang: str) -> bool:
        """True if an already-detected `lang` may be kept as-is.

        Allowed languages and uncertain results (``unknown``) are kept; only a
        confident non-allowed detection returns False. Split out from
        ``is_allowed`` so callers that translate can detect once and reuse the
        label (see pipeline language step).
        """
        if lang in LANGS:
            return True
        if lang == "unknown":           # uncertain -> keep (conservative)
            return True
        return False                     # confident non-allowed

    def is_allowed(self, text: str) -> bool:
        return self.lang_allowed(self.detect(text))
