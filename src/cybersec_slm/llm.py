#!/usr/bin/env python3
"""Shared NVIDIA NIM (OpenAI-compatible) chat access.

The dashboard's agent already talked to NIM, but its client lived in
``dashboard.agent_client``. Sourcing needs the same model to judge catalog rows,
and a sourcing module importing the dashboard would invert the layering (the
dashboard reads the pipeline, never the other way round), so the client itself
lives here and both sides call it.

The ``openai`` SDK is imported lazily inside :func:`client`, so this module
imports cleanly without the optional ``agent`` extra; :func:`is_available` is how
a caller checks before offering a model-backed feature.

Nothing here knows what it is being asked — no prompts, no parsing. Callers own
their prompt and their reading of the reply, and are tested against a fake client
rather than a real NIM call.
"""

from __future__ import annotations

import importlib.util
import os

DEFAULT_MODEL = "meta/llama-3.1-8b-instruct"
DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1"
# A model that stalls must surface as an error, never hang a run: the SDK's own
# default is 600s.
DEFAULT_TIMEOUT = 60.0

API_KEY_VAR = "NVIDIA_API_KEY"
BASE_URL_VAR = "CYBERSEC_SLM_NIM_BASE_URL"
MODEL_VAR = "CYBERSEC_SLM_NIM_MODEL"


class LLMUnavailable(RuntimeError):
    """Raised when NIM cannot be reached: no ``openai`` extra, or no API key.

    A caller that curates the corpus must fail on this rather than degrade to
    something weaker, which would look like a model verdict while not being one.
    """


def is_available() -> bool:
    """Whether a NIM call can be made: the ``agent`` extra is installed and a key set."""
    return (importlib.util.find_spec("openai") is not None
            and bool(os.environ.get(API_KEY_VAR)))


def model() -> str:
    """The NIM model to use (``$CYBERSEC_SLM_NIM_MODEL`` overrides the default)."""
    return os.environ.get(MODEL_VAR) or DEFAULT_MODEL


def client():
    """An OpenAI-SDK client pointed at NIM; raises :class:`LLMUnavailable`.

    Checked rather than assumed: without this, a missing key surfaces as a bare
    KeyError from deep inside a worker.
    """
    if importlib.util.find_spec("openai") is None:
        raise LLMUnavailable(
            "the 'openai' package is not installed — install the 'agent' extra "
            "(uv sync --extra agent)")
    api_key = os.environ.get(API_KEY_VAR)
    if not api_key:
        raise LLMUnavailable(f"${API_KEY_VAR} is not set")
    from openai import OpenAI
    return OpenAI(api_key=api_key,
                  base_url=os.environ.get(BASE_URL_VAR, DEFAULT_BASE_URL),
                  timeout=DEFAULT_TIMEOUT, max_retries=1)


def ask(system: str, user: str, *, cli=None, temperature: float = 0.0) -> str:
    """One non-streaming completion; returns the reply text (``""`` if empty).

    ``cli`` injects a client (the test seam — every caller is tested against a
    fake, never a live NIM call). ``temperature`` defaults to 0 because these are
    judgements, not prose: the same row should get the same verdict as often as
    the model can manage.
    """
    cli = cli or client()
    resp = cli.chat.completions.create(
        model=model(),
        temperature=temperature,
        messages=[{"role": "system", "content": system},
                  {"role": "user", "content": user}],
    )
    return (resp.choices[0].message.content or "").strip()
