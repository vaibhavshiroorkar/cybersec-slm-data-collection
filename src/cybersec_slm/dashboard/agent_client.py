#!/usr/bin/env python3
"""NVIDIA NIM (OpenAI-compatible) chat client + the agent's tool-calling loop.

Talks to NIM via the standard ``openai`` SDK, imported lazily inside
``_client()`` so this module imports cleanly even when the optional ``agent``
extra isn't installed -- ``is_available()`` is how a page checks before
rendering a chat box. No Streamlit import; the tool-calling loop is tested
against a fake client (see tests/dashboard/test_agent_client.py), never a
real NIM call.
"""

from __future__ import annotations

import importlib.util
import json
import os

from . import agent_tools

DEFAULT_MODEL = "meta/llama-3.3-70b-instruct"
DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1"
MAX_TOOL_ITERATIONS = 6

SYSTEM_PROMPT = (
    "You are a read-only assistant for the cybersec-slm data pipeline "
    "dashboard. Answer questions about the pipeline's run status, EDA gate, "
    "sources, manifest, and the corpus itself using only the provided tools. "
    "You cannot trigger a run, retry a source, or modify anything -- you can "
    "only read what has already been written. If a tool returns no data, say "
    "so plainly instead of guessing."
)

TOOL_FUNCTIONS = {
    "get_pipeline_status": agent_tools.get_pipeline_status,
    "get_eda_status": agent_tools.get_eda_status,
    "get_manifest_summary": agent_tools.get_manifest_summary,
    "get_source_table": agent_tools.get_source_table,
    "get_stage_reports": agent_tools.get_stage_reports,
    "search_dataset": agent_tools.search_dataset,
    "get_rejected_or_dupes": agent_tools.get_rejected_or_dupes,
}

TOOL_SPECS = [
    {"type": "function", "function": {
        "name": "get_pipeline_status",
        "description": "Is a pipeline run currently active, how many sources have "
                        "completed so far, and the tail of the current run's log.",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "get_eda_status",
        "description": "The most recent EDA sufficiency gate result: pass/fail, "
                        "blocking issues, warnings, and headline metrics.",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "get_manifest_summary",
        "description": "Release manifest summary: record/token counts and the "
                        "domain/subdomain/source/language/license breakdown.",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "get_source_table",
        "description": "Per-source summary rows (name, sub-domain, license, row count).",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "get_stage_reports",
        "description": "Cleaning and normalization stage totals (records in/out, "
                        "rejects, paused sources).",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "search_dataset",
        "description": "Keyword substring search over the collected corpus, "
                        "optionally filtered by domain/subdomain/source/record_type/lang. "
                        "Returns trimmed text excerpts, not full records.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string",
                          "description": "Case-insensitive substring to search for in "
                                         "record text. Empty matches all records."},
                "domain": {"type": "string", "description": "Filter to this domain name."},
                "subdomain": {"type": "string", "description": "Filter to this subdomain name."},
                "source": {"type": "string", "description": "Filter to this source name."},
                "record_type": {"type": "string", "description": "Filter to this record type."},
                "lang": {"type": "string", "description": "Filter to this language code."},
                "limit": {"type": "integer",
                          "description": "Max matching records to return (default 10, max 25)."},
            },
        },
    }},
    {"type": "function", "function": {
        "name": "get_rejected_or_dupes",
        "description": "Preview records that didn't make it into the corpus.",
        "parameters": {
            "type": "object",
            "properties": {
                "kind": {"type": "string", "enum": ["rejected", "duplicates", "dedup_scores"],
                          "description": "Which sink to preview."},
                "limit": {"type": "integer",
                          "description": "Max records to return (default 10, max 25)."},
            },
            "required": ["kind"],
        },
    }},
]


def is_available() -> bool:
    """Whether the Agent page can render a chat box: the `agent` extra is
    installed and an API key is set."""
    return (importlib.util.find_spec("openai") is not None
            and bool(os.environ.get("NVIDIA_API_KEY")))


def _client():
    from openai import OpenAI
    return OpenAI(api_key=os.environ["NVIDIA_API_KEY"],
                  base_url=os.environ.get("CYBERSEC_SLM_NIM_BASE_URL", DEFAULT_BASE_URL))


def _call_tool(name: str, args: dict):
    fn = TOOL_FUNCTIONS.get(name)
    if fn is None:
        return {"error": f"unknown tool: {name}"}
    try:
        return fn(**args)
    except Exception as exc:  # boundary: args come from the model, never trust them
        return {"error": str(exc)}


def ask(history: list[dict], client=None) -> dict:
    """Answer the latest question in ``history`` (a list of plain
    ``{"role","content"}`` user/assistant turns -- the caller owns persisting
    this across turns; tool-call bookkeeping stays internal to this call).

    Returns ``{"answer": str, "trace": [{"tool","args","result"}], "error":
    str | None}``. On an error talking to NIM -- including building the
    client itself (missing API key, `openai` not installed) -- ``answer`` is
    empty and ``error`` is set. Tool exceptions never raise here -- they
    become an ``{"error": ...}`` tool result the model sees and can react to.
    """
    model = os.environ.get("CYBERSEC_SLM_NIM_MODEL", DEFAULT_MODEL)
    messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}, *history]
    trace: list[dict] = []
    try:
        client = client or _client()
        for _ in range(MAX_TOOL_ITERATIONS):
            resp = client.chat.completions.create(
                model=model, messages=messages, tools=TOOL_SPECS, tool_choice="auto")
            msg = resp.choices[0].message
            tool_calls = getattr(msg, "tool_calls", None)
            if not tool_calls:
                return {"answer": msg.content or "", "trace": trace, "error": None}
            messages.append({
                "role": "assistant", "content": msg.content,
                "tool_calls": [{"id": tc.id, "type": "function",
                                "function": {"name": tc.function.name,
                                             "arguments": tc.function.arguments}}
                               for tc in tool_calls],
            })
            for tc in tool_calls:
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                result = _call_tool(tc.function.name, args)
                trace.append({"tool": tc.function.name, "args": args, "result": result})
                messages.append({"role": "tool", "tool_call_id": tc.id,
                                  "content": json.dumps(result, default=str)})
        return {"answer": "I stopped after too many lookups without reaching a final "
                          "answer -- try asking a narrower question.",
                "trace": trace, "error": None}
    except Exception as exc:  # boundary: any NIM/network failure (auth, rate limit, timeout)
        return {"answer": "", "trace": trace, "error": str(exc)}
