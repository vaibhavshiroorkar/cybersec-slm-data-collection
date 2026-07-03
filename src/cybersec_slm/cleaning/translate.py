#!/usr/bin/env python3
"""Translation — render non-English text into English instead of dropping it.

Backends, in preference order:
  1. deep-translator (GoogleTranslator)  — online, auto source detection, no
     model download; chunks long text to stay under the request size limit.
  2. argostranslate                      — fully offline, needs per-language
     packages installed (from_code -> en).
  3. none                                — no backend available; translation is a
     no-op and callers fall back to their drop policy.

Conservative policy: ``translate`` returns ``(text, ok)``. ``ok`` is True only
when a backend actually produced a translation. On any failure (no backend,
network error, missing language package) it returns the original text with
``ok=False`` so the caller can decide what to do (keep, drop, flag).

Public API:
    tr = Translator()
    new_text, ok = tr.translate(text, src="fr")   # src is a hint; may be None
"""

from __future__ import annotations

import concurrent.futures as _cf
import os
import re

from .common import logger, try_import

# Operator kill switch: set to a falsey value (off/0/false/no/none) to skip
# online translation entirely, so callers drop non-English instead of paying
# slow per-record network calls. Mirrors CYBERSEC_SLM_ENFORCE_* env gates.
_TRANSLATE_OFF = {"off", "0", "false", "no", "none"}

# Google's free endpoint rejects requests over ~5000 chars; stay well under.
_MAX_CHUNK = 4500
_PARA_RE = re.compile(r"\n{2,}")

# Resilience guards for the online backend. The free Google endpoint rate-limits
# aggressively; without these a blocked endpoint hangs the whole run (each record
# fans out into chunked HTTP calls that each stall near the TCP timeout).
_CALL_TIMEOUT = 20          # max seconds for one record's translation
_MAX_CONSEC_FAILS = 6       # consecutive failures -> disable the online backend
_MAX_CHUNKS = 8             # cap chunks/record so one huge text can't fan out forever


def _normalize_code(code: str | None) -> str | None:
    """Reduce a detected label (e.g. 'zh-cn', '__label__de') to a base code."""
    if not code:
        return None
    code = code.replace("__label__", "").strip().lower()
    if not code or code in ("unknown", "non-latin"):
        return None
    return code.split("-")[0]


def _chunk(text: str, limit: int = _MAX_CHUNK) -> list[str]:
    """Split text into <=limit pieces on paragraph, then line, then hard cuts."""
    if len(text) <= limit:
        return [text]
    chunks: list[str] = []
    buf = ""
    for para in _PARA_RE.split(text):
        piece = (buf + "\n\n" + para) if buf else para
        if len(piece) <= limit:
            buf = piece
            continue
        if buf:
            chunks.append(buf)
            buf = ""
        if len(para) <= limit:
            buf = para
            continue
        # A single oversized paragraph: fall back to hard slicing.
        for i in range(0, len(para), limit):
            chunks.append(para[i:i + limit])
    if buf:
        chunks.append(buf)
    return chunks


class Translator:
    def __init__(self, backend="auto", target="en"):
        if os.environ.get("CYBERSEC_SLM_TRANSLATE", "").strip().lower() in _TRANSLATE_OFF:
            backend = "off"            # env kill switch overrides the requested backend
        self.target = target
        self.backend = "none"
        self._google = None
        self._argos = None
        self._consec_fail = 0       # consecutive online-backend failures
        self._pool = None           # lazy single-thread pool for per-call timeouts

        if backend in ("auto", "google", "deep-translator"):
            dt = try_import("deep_translator")
            if dt is not None:
                try:
                    # Probe construction so a broken install fails here, not mid-run.
                    self._google = dt.GoogleTranslator
                    self._google(source="auto", target=target)
                    self.backend = "google"
                except Exception as ex:
                    logger.warning(f"translate: deep-translator init failed "
                                   f"({type(ex).__name__})")
                    self._google = None
        if self.backend == "none" and backend in ("auto", "argos", "argostranslate"):
            argos = try_import("argostranslate.translate")
            if argos is not None:
                self._argos = argos
                self.backend = "argos"
        if self.backend == "none" and backend not in ("auto", "none", "off"):
            logger.warning(f"translate: backend '{backend}' requested but unavailable")
        logger.debug(f"translate: backend = {self.backend}")

    @property
    def available(self) -> bool:
        return self.backend != "none"

    def translate(self, text: str, src: str | None = None) -> tuple[str, bool]:
        if not text or not text.strip() or not self.available:
            return text, False
        try:
            if self.backend == "google":
                result = self._run_with_timeout(self._translate_google, text)
            elif self.backend == "argos":
                result = self._translate_argos(text, src)
            else:
                return text, False
            self._consec_fail = 0           # success resets the breaker
            return result, True
        except Exception as ex:
            self._consec_fail += 1
            logger.warning(f"translate: {self.backend} failed ({type(ex).__name__})")
            # Circuit breaker: a sustained outage (rate-limit/block) means every
            # further call will also stall, so stop trying and let callers apply
            # their drop policy — otherwise one source hangs the entire run.
            if self.backend == "google" and self._consec_fail >= _MAX_CONSEC_FAILS:
                logger.error(f"translate: disabling google backend after "
                             f"{self._consec_fail} consecutive failures "
                             f"(rate-limited/blocked); non-English now dropped")
                self.backend = "none"
            return text, False

    def _run_with_timeout(self, fn, *args):
        """Run a backend call with a hard wall-clock cap (a hung HTTP request
        cannot otherwise be interrupted). The orphaned worker is left to finish
        on its own; the breaker stops us from queuing many more behind it."""
        if self._pool is None:
            self._pool = _cf.ThreadPoolExecutor(max_workers=1,
                                                thread_name_prefix="translate")
        return self._pool.submit(fn, *args).result(timeout=_CALL_TIMEOUT)

    # ----------------------------------------------------------- backends ----
    def _translate_google(self, text: str) -> str:
        tr = self._google(source="auto", target=self.target)
        chunks = _chunk(text)
        if len(chunks) > _MAX_CHUNKS:           # cap fan-out for very long texts
            chunks = chunks[:_MAX_CHUNKS]
        out = []
        for chunk in chunks:
            if not chunk.strip():
                out.append(chunk)
                continue
            res = tr.translate(chunk)
            out.append(res if res is not None else chunk)
        return "\n\n".join(out) if len(out) > 1 else out[0]

    def _translate_argos(self, text: str, src: str | None) -> str:
        from_code = _normalize_code(src)
        if not from_code:
            raise ValueError("argos needs a source language code")
        # translate_text(text, from_code, to_code) raises if no package installed.
        return self._argos.translate(text, from_code, self.target)
