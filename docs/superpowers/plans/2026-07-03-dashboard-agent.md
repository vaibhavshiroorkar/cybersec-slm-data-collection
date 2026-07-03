# Dashboard Q&A Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a third Streamlit dashboard page (`pages/3_Agent.py`) that answers questions about pipeline status and corpus content via an NVIDIA NIM tool-calling agent, grounded entirely in read-only wrappers over the existing `data.py` read layer.

**Architecture:** Three new files under `src/cybersec_slm/dashboard/`: `agent_tools.py` (pure, Streamlit-free wrappers over `data.py`), `agent_client.py` (the NIM tool-calling loop against the OpenAI-compatible `openai` SDK, testable with a fake client), and `pages/3_Agent.py` (the chat UI, presentation-only, following the existing `pages/1_Pipeline.py` / `pages/2_Dataset.py` pattern).

**Tech Stack:** Python 3.13, Streamlit (existing `dashboard` extra), `openai` SDK pointed at NVIDIA NIM's OpenAI-compatible endpoint (new `agent` extra), pytest.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-03-dashboard-agent-design.md` — read it first if anything below is unclear.
- Python >= 3.13 (`pyproject.toml` `requires-python`).
- New dependency floor: `openai>=1.0`, added only as an opt-in extra (`agent`), never a core dependency — plain `uv sync` must stay lean.
- No Streamlit import in `agent_tools.py` or `agent_client.py` — both must import and run fully with `streamlit` absent, so they can be unit-tested headlessly like `data.py`.
- Every agent tool is read-only: it may only read artifacts already on disk via `data.py`. No tool may trigger a run, retry a source, or write a file.
- Chat history lives only in `st.session_state` — never written to disk, and never sent as a persisted tool-call transcript (only plain `{"role","content"}` turns cross the `ask()` boundary; the tool round-trip is internal to a single `ask()` call).
- The tool-calling loop is capped at `MAX_TOOL_ITERATIONS = 6`. Tests must never call the real NVIDIA API — always inject a fake client.
- The Agent page must render without raising when `NVIDIA_API_KEY` is unset or the `agent` extra isn't installed — it shows setup instructions instead of a chat box (mirrors how `dashboard/launch.py` degrades when `streamlit` isn't installed).
- Match existing dashboard file conventions: `from __future__ import annotations`, a module docstring stating the file's one job, `#!/usr/bin/env python3` shebang line, ruff clean (line-length 100, rules in `pyproject.toml`).

---

### Task 1: `agent_tools.py` — read-only tool wrappers

**Files:**
- Create: `src/cybersec_slm/dashboard/agent_tools.py`
- Test: `tests/dashboard/test_agent_tools.py`

**Interfaces:**
- Consumes: `cybersec_slm.dashboard.data` — `run_status()`, `live_progress(tail)`, `latest_eda()`, `manifest()`, `source_table()`, `clean_report()`, `normalize_report()`, `dataset_page(filters, search, offset, limit)`, `sidecar(kind, limit)`, `FILTER_FIELDS`. All already implemented and unchanged.
- Produces (consumed by Task 2's `agent_client.py`):
  - `get_pipeline_status() -> dict` — `{"state", "age_seconds", "sources_completed", "sources_total", "log_tail"}`
  - `get_eda_status() -> dict` — `{"available": False}` or `{"available": True, "passed", "ts", "blockers", "warnings", "metrics"}`
  - `get_manifest_summary() -> dict` — `{"available": False}` or `{"available": True, "record_count", "token_total", "domains", "subdomains", "sources", "languages", "licenses"}`
  - `get_source_table() -> list[dict]`
  - `get_stage_reports() -> dict` — `{"clean": dict | None, "normalize": dict | None}`
  - `search_dataset(query="", domain=None, subdomain=None, source=None, record_type=None, lang=None, limit=10) -> dict` — `{"rows": [{"id","source","subdomain","record_type","lang","token_count","text_excerpt"}], "match_count", "capped"}`
  - `get_rejected_or_dupes(kind="rejected", limit=10) -> list[dict]`

- [ ] **Step 1: Write the failing tests**

Create `tests/dashboard/test_agent_tools.py`:

```python
"""Headless tests for the agent's read-only tool wrappers (no Streamlit, no network)."""

import json
import os

from cybersec_slm.dashboard import agent_tools


def _seed(root: str) -> None:
    """Write a minimal but realistic set of pipeline artifacts under `root`."""
    logs = os.path.join(root, "logs")
    eda = os.path.join(logs, "eda")
    final = os.path.join(root, "data", "final")
    os.makedirs(eda, exist_ok=True)
    os.makedirs(final, exist_ok=True)

    report = {
        "ts": "2026-07-02T10:00:00", "passed": False,
        "metrics": {"total": 900, "num_subdomains": 2,
                    "dup_rate": 0.02, "text_quality": {"avg_tokens": 110}},
        "violations": [{"severity": "blocker", "check": "volume", "message": "too few records"},
                       {"severity": "warning", "check": "subdomain_volume", "message": "iam thin"}],
    }
    with open(os.path.join(eda, "latest.json"), "w", encoding="utf-8") as f:
        json.dump(report, f)

    with open(os.path.join(logs, "final_table.csv"), "w", encoding="utf-8", newline="") as f:
        f.write("Name,Sub-Domain,License,Total Lines\n"
                "nvd,vuln-mgmt,Public Domain,900\n")

    with open(os.path.join(logs, "clean_report.csv"), "w", encoding="utf-8", newline="") as f:
        f.write("sub_domain,source,file,in,out,struct_dropped,exact_dups\n"
                "vuln-mgmt,nvd,a.jsonl,10,8,1,1\n"
                "TOTAL,,1 files,10,8,1,1\n")

    with open(os.path.join(logs, "normalize_report.json"), "w", encoding="utf-8") as f:
        json.dump({"counts": {"in": 10, "written": 8, "rejected": 1}, "paused_sources": []}, f)

    with open(os.path.join(logs, "completed_sources.txt"), "w", encoding="utf-8") as f:
        f.write("hf:a\nurl:b\n")

    with open(os.path.join(logs, "pipeline.123.log"), "w", encoding="utf-8") as f:
        f.write("10:00:00 === source: hf a ===\n10:00:01 done\n")

    manifest = {
        "record_count": 4, "token_total": 480,
        "domains": {"vuln": 3, "iam": 1}, "subdomains": {"vuln-mgmt": 3, "iam": 1},
        "sources": {"nvd": 3, "iam-docs": 1}, "licenses": {"Public Domain": 3, "CC-BY": 1},
        "languages": {"en": 4},
    }
    with open(os.path.join(final, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f)

    recs = [
        {"id": "1", "source": "nvd", "domain_name": "vuln", "subdomain_name": "vuln-mgmt",
         "record_type": "cve", "lang": "en", "token_count": 120,
         "text": "Heap overflow in the parser allows remote code execution"},
        {"id": "2", "source": "iam-docs", "domain_name": "iam", "subdomain_name": "iam",
         "record_type": "doc", "lang": "en", "token_count": 90,
         "text": "Rotate service account keys every ninety days"},
    ]
    with open(os.path.join(final, "dataset.jsonl"), "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
    with open(os.path.join(final, "rejected.jsonl"), "w", encoding="utf-8") as f:
        f.write(json.dumps({"id": "9", "source": "bad",
                            "reason": "domain not in allowlist"}) + "\n")


def test_pipeline_status(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    status = agent_tools.get_pipeline_status()
    assert status["state"] == "running"
    assert status["sources_completed"] == 2
    assert any("source: hf" in ln for ln in status["log_tail"])


def test_eda_status(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    eda = agent_tools.get_eda_status()
    assert eda["available"] is True
    assert eda["passed"] is False
    assert [v["check"] for v in eda["blockers"]] == ["volume"]
    assert [v["check"] for v in eda["warnings"]] == ["subdomain_volume"]


def test_eda_status_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    assert agent_tools.get_eda_status() == {"available": False}


def test_manifest_summary(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    man = agent_tools.get_manifest_summary()
    assert man["available"] is True
    assert man["record_count"] == 4
    assert man["sources"] == {"nvd": 3, "iam-docs": 1}


def test_manifest_summary_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    assert agent_tools.get_manifest_summary() == {"available": False}


def test_source_table(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    rows = agent_tools.get_source_table()
    assert len(rows) == 1 and rows[0]["Name"] == "nvd"


def test_stage_reports(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    reports = agent_tools.get_stage_reports()
    assert reports["clean"]["out"] == "8"
    assert reports["normalize"]["counts"]["written"] == 8


def test_search_dataset_matches_and_trims(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    result = agent_tools.search_dataset(query="rotate")
    assert result["match_count"] == 1
    row = result["rows"][0]
    assert row["id"] == "2"
    assert row["text_excerpt"].startswith("Rotate service account keys")
    assert set(row) == {"id", "source", "subdomain", "record_type", "lang",
                        "token_count", "text_excerpt"}


def test_search_dataset_filters_by_facet(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    result = agent_tools.search_dataset(subdomain="iam")
    assert result["match_count"] == 1 and result["rows"][0]["id"] == "2"


def test_search_dataset_limit_clamped_up_from_zero(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    result = agent_tools.search_dataset(limit=0)
    assert len(result["rows"]) == 1   # clamped to at least 1, not 0


def test_rejected_or_dupes(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    _seed(str(tmp_path))
    rows = agent_tools.get_rejected_or_dupes("rejected")
    assert rows[0]["reason"].startswith("domain")
    assert agent_tools.get_rejected_or_dupes("duplicates") == []


def test_bare_root_degrades_gracefully(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))   # nothing seeded
    assert agent_tools.get_pipeline_status()["state"] == "idle"
    assert agent_tools.get_pipeline_status()["sources_completed"] == 0
    assert agent_tools.get_eda_status() == {"available": False}
    assert agent_tools.get_manifest_summary() == {"available": False}
    assert agent_tools.get_source_table() == []
    assert agent_tools.get_stage_reports() == {"clean": None, "normalize": None}
    assert agent_tools.search_dataset() == {"rows": [], "match_count": 0, "capped": False}
    assert agent_tools.get_rejected_or_dupes("rejected") == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/dashboard/test_agent_tools.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybersec_slm.dashboard.agent_tools'`

- [ ] **Step 3: Write the implementation**

Create `src/cybersec_slm/dashboard/agent_tools.py`:

```python
#!/usr/bin/env python3
"""Read-only tool wrappers for the dashboard's Q&A agent.

Each function wraps :mod:`cybersec_slm.dashboard.data` and trims its output to
something small enough for an LLM's context window. Pure functions -> plain
dict/list; no Streamlit import, no network call, so every function is
unit-tested the same way ``data.py`` is: seed a tmp data root, call, assert.
"""

from __future__ import annotations

from . import data

_MAX_TEXT_EXCERPT = 200
_MAX_SEARCH_LIMIT = 25
_MAX_SIDECAR_LIMIT = 25


def get_pipeline_status() -> dict:
    """Is a run active, how many sources have completed, and the recent log tail."""
    status = data.run_status()
    prog = data.live_progress(tail=10)
    return {
        "state": status["state"],
        "age_seconds": status.get("age"),
        "sources_completed": prog["completed"],
        "sources_total": prog.get("total"),
        "log_tail": prog.get("log_tail", []),
    }


def get_eda_status() -> dict:
    """The most recent EDA sufficiency gate result (pass/fail, blockers, warnings, metrics)."""
    eda = data.latest_eda()
    if not eda:
        return {"available": False}
    violations = eda.get("violations", []) or []
    return {
        "available": True,
        "passed": eda.get("passed"),
        "ts": eda.get("ts"),
        "blockers": [v for v in violations if v.get("severity") == "blocker"],
        "warnings": [v for v in violations if v.get("severity") == "warning"],
        "metrics": eda.get("metrics", {}),
    }


def get_manifest_summary() -> dict:
    """Record/token counts and the domain/subdomain/source/language/license facets."""
    man = data.manifest()
    if not man:
        return {"available": False}
    return {
        "available": True,
        "record_count": man.get("record_count"),
        "token_total": man.get("token_total"),
        "domains": man.get("domains", {}),
        "subdomains": man.get("subdomains", {}),
        "sources": man.get("sources", {}),
        "languages": man.get("languages", {}),
        "licenses": man.get("licenses", {}),
    }


def get_source_table() -> list[dict]:
    """Per-source size/row-count/license summary rows."""
    return data.source_table()


def get_stage_reports() -> dict:
    """Cleaning and normalization stage totals."""
    return {"clean": data.clean_report().get("total"), "normalize": data.normalize_report()}


def search_dataset(query: str = "", domain: str | None = None, subdomain: str | None = None,
                    source: str | None = None, record_type: str | None = None,
                    lang: str | None = None, limit: int = 10) -> dict:
    """Keyword substring + facet search over the corpus; trimmed snippets, not full text."""
    filters = {k: v for k, v in {
        "domain": domain, "subdomain": subdomain, "source": source,
        "record_type": record_type, "lang": lang,
    }.items() if v}
    limit = max(1, min(int(limit or 10), _MAX_SEARCH_LIMIT))
    result = data.dataset_page(filters=filters, search=query or "", offset=0, limit=limit)
    rows = [{
        "id": r.get("id"), "source": r.get("source"), "subdomain": r.get("subdomain_name"),
        "record_type": r.get("record_type"), "lang": r.get("lang"),
        "token_count": r.get("token_count"),
        "text_excerpt": (r.get("text") or "")[:_MAX_TEXT_EXCERPT],
    } for r in result["rows"]]
    return {"rows": rows, "match_count": result["match_count"], "capped": result["capped"]}


def get_rejected_or_dupes(kind: str = "rejected", limit: int = 10) -> list[dict]:
    """Preview records that didn't make it into the corpus (``kind`` selects the sink)."""
    limit = max(1, min(int(limit or 10), _MAX_SIDECAR_LIMIT))
    return data.sidecar(kind, limit=limit)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/dashboard/test_agent_tools.py -v`
Expected: PASS (12 tests)

- [ ] **Step 5: Lint and commit**

Run: `uv run ruff check src/cybersec_slm/dashboard/agent_tools.py tests/dashboard/test_agent_tools.py`
Expected: no errors

```bash
git add src/cybersec_slm/dashboard/agent_tools.py tests/dashboard/test_agent_tools.py
git commit -m "dashboard: read-only tool wrappers for the Q&A agent"
```

---

### Task 2: `agent_client.py` — NIM tool-calling loop + `agent` extra

**Files:**
- Create: `src/cybersec_slm/dashboard/agent_client.py`
- Modify: `pyproject.toml` (new `agent` optional-dependency group)
- Test: `tests/dashboard/test_agent_client.py`

**Interfaces:**
- Consumes: `cybersec_slm.dashboard.agent_tools` — all seven functions from Task 1, called by exact name.
- Produces (consumed by Task 3's `pages/3_Agent.py`):
  - `is_available() -> bool`
  - `ask(history: list[dict], client=None) -> dict` — returns `{"answer": str, "trace": list[{"tool","args","result"}], "error": str | None}`
  - `MAX_TOOL_ITERATIONS: int` (module constant, `6`)

- [ ] **Step 1: Add the `agent` optional dependency**

In `pyproject.toml`, find this block (the `dashboard` extra):

```toml
# Local-first monitoring + dataset-exploration dashboard (`cybersec-slm dashboard`).
# Streamlit bundles Altair, so charts need no extra dependency. Opt-in because the
# core pipeline never needs a web server:  uv sync --extra dashboard
dashboard = [
    "streamlit>=1.40",
]
```

Add immediately after it:

```toml

# Q&A agent on the dashboard's Agent page (`pages/3_Agent.py`), backed by
# NVIDIA NIM. NIM exposes an OpenAI-compatible endpoint, so the standard
# `openai` SDK works unmodified by pointing `base_url` at NIM. Opt-in, same as
# `dashboard`:  uv sync --extra dashboard --extra agent
agent = [
    "openai>=1.0",
]
```

- [ ] **Step 2: Write the failing tests**

Create `tests/dashboard/test_agent_client.py`:

```python
"""Tests for the agent's tool-calling loop against a fake OpenAI-compatible
client. No real NIM calls, and the `openai` package is never imported here."""

from __future__ import annotations

from types import SimpleNamespace

from cybersec_slm.dashboard import agent_client


def _tool_call(call_id, name, arguments):
    return SimpleNamespace(id=call_id, function=SimpleNamespace(name=name, arguments=arguments))


def _response(content=None, tool_calls=None):
    message = SimpleNamespace(content=content, tool_calls=tool_calls)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


class _FakeClient:
    """Returns one canned response per call, in the order given."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        return self._responses.pop(0)


def test_final_answer_with_no_tool_calls():
    client = _FakeClient([_response(content="hello there")])
    result = agent_client.ask([{"role": "user", "content": "hi"}], client=client)
    assert result == {"answer": "hello there", "trace": [], "error": None}
    assert len(client.calls) == 1


def test_executes_requested_tool_then_returns_final_answer(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))   # bare root -> idle
    client = _FakeClient([
        _response(tool_calls=[_tool_call("call_1", "get_pipeline_status", "{}")]),
        _response(content="the pipeline is idle"),
    ])
    result = agent_client.ask([{"role": "user", "content": "is a run active?"}], client=client)
    assert result["answer"] == "the pipeline is idle"
    assert result["error"] is None
    assert len(result["trace"]) == 1
    assert result["trace"][0]["tool"] == "get_pipeline_status"
    assert result["trace"][0]["result"]["state"] == "idle"
    assert len(client.calls) == 2


def test_unknown_tool_becomes_error_result_not_a_crash():
    client = _FakeClient([
        _response(tool_calls=[_tool_call("call_1", "delete_everything", "{}")]),
        _response(content="I can't do that"),
    ])
    result = agent_client.ask([{"role": "user", "content": "delete the corpus"}], client=client)
    assert result["trace"][0]["result"] == {"error": "unknown tool: delete_everything"}
    assert result["answer"] == "I can't do that"


def test_stops_after_max_iterations_if_model_never_finishes():
    endless = [_response(tool_calls=[_tool_call(f"call_{i}", "get_pipeline_status", "{}")])
               for i in range(agent_client.MAX_TOOL_ITERATIONS)]
    client = _FakeClient(endless)
    result = agent_client.ask([{"role": "user", "content": "loop forever"}], client=client)
    assert result["error"] is None
    assert "too many lookups" in result["answer"]
    assert len(result["trace"]) == agent_client.MAX_TOOL_ITERATIONS


def test_api_exception_is_reported_not_raised():
    class _BoomClient:
        def __init__(self):
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

        def _create(self, **kwargs):
            raise RuntimeError("connection refused")

    result = agent_client.ask([{"role": "user", "content": "hi"}], client=_BoomClient())
    assert result["answer"] == ""
    assert result["error"] == "connection refused"


def test_is_available_false_without_openai_installed_or_key(monkeypatch):
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    assert agent_client.is_available() is False
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/dashboard/test_agent_client.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybersec_slm.dashboard.agent_client'`

- [ ] **Step 4: Write the implementation**

Create `src/cybersec_slm/dashboard/agent_client.py`:

```python
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
    str | None}``. On an error talking to NIM, ``answer`` is empty and
    ``error`` is set. Tool exceptions never raise here -- they become an
    ``{"error": ...}`` tool result the model sees and can react to.
    """
    client = client or _client()
    model = os.environ.get("CYBERSEC_SLM_NIM_MODEL", DEFAULT_MODEL)
    messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}, *history]
    trace: list[dict] = []
    try:
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/dashboard/test_agent_client.py -v`
Expected: PASS (6 tests)

- [ ] **Step 6: Lint and commit**

Run: `uv run ruff check src/cybersec_slm/dashboard/agent_client.py tests/dashboard/test_agent_client.py`
Expected: no errors

```bash
git add pyproject.toml src/cybersec_slm/dashboard/agent_client.py tests/dashboard/test_agent_client.py
git commit -m "dashboard: NVIDIA NIM tool-calling loop for the Q&A agent"
```

---

### Task 3: `pages/3_Agent.py` — chat UI

**Files:**
- Create: `src/cybersec_slm/dashboard/pages/3_Agent.py`
- Modify: `tests/dashboard/test_app_smoke.py`

**Interfaces:**
- Consumes: `cybersec_slm.dashboard.agent_client` — `is_available()`, `ask(history)` from Task 2.
- Produces: nothing consumed by later tasks (this is the leaf UI).

- [ ] **Step 1: Write the failing test**

In `tests/dashboard/test_app_smoke.py`, add this test after
`test_page_renders_without_error` (keep the existing imports and
`_seed_minimal` as-is):

```python
def test_agent_page_shows_setup_instructions_when_not_configured(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSEC_SLM_DATA_ROOT", str(tmp_path))
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    _seed_minimal(str(tmp_path))
    at = AppTest.from_file(os.path.join(_DASH, "pages/3_Agent.py"), default_timeout=30)
    at.run()
    assert not at.exception
    assert any("uv sync --extra agent" in info.value for info in at.info)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/dashboard/test_app_smoke.py -k agent_page -v`
Expected: FAIL — `AppTest.from_file` errors because `pages/3_Agent.py` doesn't exist

- [ ] **Step 3: Write the implementation**

Create `src/cybersec_slm/dashboard/pages/3_Agent.py`:

```python
#!/usr/bin/env python3
"""Agent page -- ask questions about pipeline status and corpus content.

Presentation only; all reads go through cybersec_slm.dashboard.agent_client,
which calls read-only tools over cybersec_slm.dashboard.agent_tools. The
agent can look things up, never trigger a run or write anything.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import agent_client

st.title("Agent")
st.caption("Ask about pipeline status or the corpus. Read-only -- it can look "
           "things up, not trigger a run or change anything.")

if not agent_client.is_available():
    st.info(
        "Not configured yet. Install the optional extra and set an API key:\n\n"
        "```bash\n"
        "uv sync --extra dashboard --extra agent\n"
        "export NVIDIA_API_KEY=...   # from build.nvidia.com\n"
        "```"
    )
else:
    if "agent_history" not in st.session_state:
        st.session_state["agent_history"] = []
    if "agent_traces" not in st.session_state:
        st.session_state["agent_traces"] = {}

    for i, msg in enumerate(st.session_state["agent_history"]):
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            trace = st.session_state["agent_traces"].get(i)
            if trace:
                with st.expander("what I looked up"):
                    for call in trace:
                        st.markdown(f"**{call['tool']}**`({call['args']})`")
                        st.json(call["result"])

    question = st.chat_input("Ask a question…")
    if question:
        st.session_state["agent_history"].append({"role": "user", "content": question})
        result = agent_client.ask(st.session_state["agent_history"])
        answer = (f"Sorry, something went wrong talking to the model: {result['error']}"
                  if result["error"] else (result["answer"] or "(no answer)"))
        st.session_state["agent_history"].append({"role": "assistant", "content": answer})
        if result["trace"]:
            st.session_state["agent_traces"][len(st.session_state["agent_history"]) - 1] = \
                result["trace"]
        st.rerun()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/dashboard/test_app_smoke.py -v`
Expected: PASS (all pages, including the new Agent test)

- [ ] **Step 5: Lint and commit**

Run: `uv run ruff check src/cybersec_slm/dashboard/pages/3_Agent.py tests/dashboard/test_app_smoke.py`
Expected: no errors

```bash
git add src/cybersec_slm/dashboard/pages/3_Agent.py tests/dashboard/test_app_smoke.py
git commit -m "dashboard: add the Agent chat page"
```

---

### Task 4: Docs

**Files:**
- Modify: `src/cybersec_slm/dashboard/README.md`
- Modify: `docs/commands.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: nothing (docs only).
- Produces: nothing (terminal task).

- [ ] **Step 1: Update the dashboard README**

In `src/cybersec_slm/dashboard/README.md`, replace the `## Layout` table:

```markdown
## Layout
| File | Role |
|---|---|
| `data.py` | **The read layer.** The only code that touches disk/SQLite; pure functions -> plain data, no Streamlit import, fully unit-tested. |
| `charts.py` | Formatting + trend-series helpers (no Streamlit). |
| `app.py` | Streamlit entrypoint / landing overview. |
| `pages/1_Pipeline.py` | Monitor: live strip + EDA gate + trends + sources + reports + manifest. |
| `pages/2_Dataset.py` | Explore: filter/search/paginate the corpus + rejected/duplicate sinks. |
```

with:

```markdown
## Layout
| File | Role |
|---|---|
| `data.py` | **The read layer.** The only code that touches disk/SQLite; pure functions -> plain data, no Streamlit import, fully unit-tested. |
| `charts.py` | Formatting + trend-series helpers (no Streamlit). |
| `agent_tools.py` | Read-only tool wrappers over `data.py` for the Agent page; no Streamlit import, fully unit-tested. |
| `agent_client.py` | NVIDIA NIM client + tool-calling loop; no Streamlit import, tested against a fake client. |
| `app.py` | Streamlit entrypoint / landing overview. |
| `pages/1_Pipeline.py` | Monitor: live strip + EDA gate + trends + sources + reports + manifest. |
| `pages/2_Dataset.py` | Explore: filter/search/paginate the corpus + rejected/duplicate sinks. |
| `pages/3_Agent.py` | Ask: a chat agent that answers pipeline/dataset questions via tool-calling. |
```

Replace the `## Pages` section:

```markdown
## Pages
- **Pipeline** — a live strip (auto-refreshing ~3s while a run is detected, from
  `completed_sources.txt` + the newest per-PID log), the EDA sufficiency gate
  (pass/fail + blockers/warnings + metrics), trend charts over past EDA runs, the
  per-source table, clean/normalize stage reports, and the release manifest.
- **Dataset** — filter by domain/subdomain/source/type/lang (facets from the
  manifest), full-text substring search, a paginated results table with a full
  22-field record detail, and previews of what was rejected or de-duplicated.
```

with:

```markdown
## Pages
- **Pipeline** — a live strip (auto-refreshing ~3s while a run is detected, from
  `completed_sources.txt` + the newest per-PID log), the EDA sufficiency gate
  (pass/fail + blockers/warnings + metrics), trend charts over past EDA runs, the
  per-source table, clean/normalize stage reports, and the release manifest.
- **Dataset** — filter by domain/subdomain/source/type/lang (facets from the
  manifest), full-text substring search, a paginated results table with a full
  22-field record detail, and previews of what was rejected or de-duplicated.
- **Agent** — a chat box that answers questions about run status, the EDA gate,
  sources, the manifest, and corpus content by calling read-only tools over the
  same data the other pages show. Every answer comes with a "what I looked up"
  trace. Needs `uv sync --extra agent` and `NVIDIA_API_KEY`; shows setup
  instructions instead of a chat box until both are present.
```

Add a bullet to the `## Notes` section (after the existing bullets):

```markdown
- The Agent page is the one exception to "no network": it calls NVIDIA NIM.
  It still writes nothing to disk — chat history lives only in the browser
  session and is lost on reload.
```

- [ ] **Step 2: Update `docs/commands.md`**

Replace the `## Dashboard` section body:

```markdown
Two pages: **Pipeline** (live run strip, EDA sufficiency gate, trends over past
runs, per-source table, stage reports, manifest) and **Dataset** (search/filter
the final corpus + the rejected/duplicate sinks). It reads whatever the pipeline
wrote under `CYBERSEC_SLM_DATA_ROOT`, so pointing that at a synced location serves a
hosted deploy without code changes. See
[src/cybersec_slm/dashboard/README.md](../src/cybersec_slm/dashboard/README.md).
```

with:

```markdown
Three pages: **Pipeline** (live run strip, EDA sufficiency gate, trends over past
runs, per-source table, stage reports, manifest), **Dataset** (search/filter
the final corpus + the rejected/duplicate sinks), and **Agent** (a chat box
answering pipeline/dataset questions via read-only tool-calling; needs
`uv sync --extra agent` and `NVIDIA_API_KEY`). It reads whatever the pipeline
wrote under `CYBERSEC_SLM_DATA_ROOT`, so pointing that at a synced location serves a
hosted deploy without code changes. See
[src/cybersec_slm/dashboard/README.md](../src/cybersec_slm/dashboard/README.md).
```

Add rows to the environment-variable table, immediately after the
`CYBERSEC_SLM_ENFORCE_LICENSE_GATE` row:

```markdown
| `NVIDIA_API_KEY` | dashboard Agent page | only for the Agent page |
| `CYBERSEC_SLM_NIM_MODEL` | dashboard Agent page (model override) | optional |
| `CYBERSEC_SLM_NIM_BASE_URL` | dashboard Agent page (NIM endpoint override) | optional |
```

- [ ] **Step 3: Update the top-level `README.md`**

Replace this line in the repo layout tree:

```markdown
  dashboard/     read-only Streamlit monitor + dataset explorer
```

with:

```markdown
  dashboard/     read-only Streamlit monitor + dataset explorer + Q&A agent
```

- [ ] **Step 4: Commit**

```bash
git add src/cybersec_slm/dashboard/README.md docs/commands.md README.md
git commit -m "docs: document the dashboard Agent page"
```

---

## Final Verification

After all four tasks:

```bash
uv sync --extra dashboard --extra agent
uv run pytest tests/dashboard -q
uv run ruff check src/cybersec_slm/dashboard tests/dashboard
```

Expected: all tests pass, ruff clean.

Manual check (requires a real `NVIDIA_API_KEY` from build.nvidia.com):

```bash
export NVIDIA_API_KEY=...
uv run cybersec-slm dashboard
```

Open the **Agent** page, ask a pipeline-status question ("is a run active?")
and a corpus-content question ("what do we have on SQL injection?"), and
confirm the "what I looked up" expander shows the actual tool calls. Then
unset `NVIDIA_API_KEY` and reload the page — confirm it shows setup
instructions instead of erroring.
