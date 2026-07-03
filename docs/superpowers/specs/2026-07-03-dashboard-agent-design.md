# Dashboard: Q&A agent page

**Status:** approved design · **Date:** 2026-07-03

## Context

The [dashboard](2026-07-02-dashboard-design.md) is a local-first, **read-only**
Streamlit app: `data.py` is the only code that touches disk, pages are
presentation-only, and there is currently zero LLM/agent code anywhere in the
pipeline.

We want a third dashboard page: a chat agent that answers questions about
**both** the pipeline/dataset (run status, EDA gate, source table, manifest
facets) and the actual **corpus content** (e.g. "what do we have on phishing
kill chains?"), grounded in what the pipeline has already written — nothing it
can't already show elsewhere in the dashboard, just reachable via natural
language instead of clicking through pages.

Decisions locked during brainstorming:
- **LLM backend:** NVIDIA NIM, via the OpenAI-compatible `openai` SDK pointed
  at NIM's `base_url`. New optional dependency, not used anywhere else in the
  pipeline.
- **Grounding strategy:** tool-calling. The model gets a fixed set of read-only
  tools (thin wrappers over existing `data.py` functions) and decides which to
  call per question, possibly chaining several.
- **Corpus search:** keyword/substring search only (reuses `data.dataset_page`'s
  existing filter + substring search). No embeddings/vector index — that's a
  materially larger scope (index build step, storage, staleness handling) and
  is explicitly out of scope for v1.
- **Read-only, still.** The agent's tools can only read artifacts already on
  disk. No tool can trigger a run, retry a source, or write anything — the
  dashboard's core guarantee is unchanged.
- **Tool transparency:** every answer is shown with a collapsible "what I
  looked up" trace (tool name + args + a truncated result), not just the final
  text.
- **Chat history is session-only** (`st.session_state`), never written to
  disk — preserves the "dashboard never writes" property. Resets on reload.

## Architecture

```
src/cybersec_slm/dashboard/
  agent_tools.py     # Thin read-only wrappers over data.py, one per tool the
                     # LLM can call. Pure functions -> plain dict/list. No
                     # Streamlit import, no network. Unit-tested like data.py.
  agent_client.py    # NIM (OpenAI-compatible) client + the tool-calling loop:
                     # send messages + tool schemas -> model requests a tool ->
                     # agent_tools executes it -> result fed back -> repeat,
                     # capped at MAX_TOOL_ITERATIONS. Returns the final answer
                     # text plus the full call trace. No Streamlit import;
                     # testable against a mocked client (no real NIM calls).
  pages/
    3_Agent.py       # Chat UI: st.chat_input/st.chat_message, session-only
                     # history, renders each answer with its trace in an
                     # st.expander. Renders setup instructions instead of a
                     # chat box when NVIDIA_API_KEY is unset.
```

- **Optional dependency group** `agent = ["openai>=1.0"]` in `pyproject.toml`
  (mirrors `dashboard`/`orchestration`). NIM exposes an OpenAI-compatible
  endpoint, so the standard `openai` SDK works unmodified by pointing
  `base_url` at NIM. Plain `uv sync` stays lean; `uv sync --extra dashboard
  --extra agent` opts in to both.
- **Config (env vars, loaded the same way the pipeline already loads
  `.env` via `python-dotenv`):**
  - `NVIDIA_API_KEY` — required to enable the page.
  - `CYBERSEC_SLM_NIM_MODEL` — default a NIM-hosted instruct model with solid
    tool-calling support (e.g. `meta/llama-3.3-70b-instruct`), overridable.
  - `CYBERSEC_SLM_NIM_BASE_URL` — default `https://integrate.api.nvidia.com/v1`.

## Tools (`agent_tools.py`)

Each wraps an existing `data.py` function and trims its output to something
context-sized for the model:

| Tool | Wraps | Purpose |
|---|---|---|
| `get_pipeline_status()` | `run_status` + `live_progress` | Is a run active, sources completed so far |
| `get_eda_status()` | `latest_eda` | Sufficiency gate pass/fail, blockers, warnings, metrics |
| `get_manifest_summary()` | `manifest` | Record count, domain/subdomain/source/language facets |
| `get_source_table()` | `source_table` | Per-source size/row-count/license summary |
| `get_stage_reports()` | `clean_report` + `normalize_report` | Clean/normalize counts, paused sources |
| `search_dataset(query, domain=None, subdomain=None, source=None, record_type=None, lang=None, limit=10)` | `dataset_page` | Keyword substring + facet search; returns trimmed snippets (id/source/subdomain/type/lang/token_count + short text excerpt) |
| `get_rejected_or_dupes(kind, limit=10)` | `sidecar` | Preview of rejected / duplicate / near-dup records |

All tools tolerate missing artifacts the same way `data.py` does (empty/None,
never raise) — a fresh checkout or a not-yet-finished run just yields "nothing
here yet" answers instead of errors.

## Data flow

1. User submits a question via `st.chat_input`; appended to
   `st.session_state` chat history.
2. `agent_client.ask(history)` sends the history + tool schemas to the NIM
   model.
3. If the model requests a tool call, `agent_client` executes it via
   `agent_tools`, appends the result to the message list, and sends again.
   Repeats until the model returns a final (non-tool-call) message or
   `MAX_TOOL_ITERATIONS` is hit.
4. The page renders the final answer as a chat bubble, with an
   `st.expander("what I looked up")` listing each `{tool, args, result}` from
   the trace.

## Safety & error handling

- Tool-loop capped at a fixed `MAX_TOOL_ITERATIONS` (e.g. 6) to bound
  latency/cost and prevent runaway loops.
- Each tool call is wrapped individually — an exception inside a tool becomes
  an error string fed back to the model (so it can report the problem or try
  another tool) rather than crashing the page.
- NIM API errors (timeout, rate limit, auth failure) are caught at the
  chat-turn level and shown as an inline error bubble; the chat stays usable
  for the next turn.
- No `NVIDIA_API_KEY` → the page shows setup instructions (which env var to
  set, and the `uv sync --extra agent` command) instead of a chat box. No
  crash, consistent with how the rest of the dashboard degrades on missing
  state.

## Testing

- `tests/dashboard/test_agent_tools.py` — headless, no Streamlit, no network.
  Same fixture style as `test_data.py` (seed a `tmp_path` data root via
  `CYBERSEC_SLM_DATA_ROOT`); asserts each tool's shape and its graceful-empty
  behavior on a bare root.
- `tests/dashboard/test_agent_client.py` — the tool-calling loop tested
  against a mocked OpenAI-compatible client (canned tool-call / final-message
  responses): verifies it executes requested tools, feeds results back,
  stops on a final message, and stops at `MAX_TOOL_ITERATIONS` if the model
  never stops requesting tools. No real NIM calls.
- `tests/dashboard/test_app_smoke.py` — extended to cover `3_Agent.py`:
  asserts it renders the "set `NVIDIA_API_KEY`" state cleanly with the key
  absent (the default in CI/test envs), same `AppTest` + `importorskip`
  pattern as the existing pages.

## Non-goals (v1, deliberate YAGNI)

Semantic/embedding search over the corpus; persisting chat history to disk;
multi-turn memory across page reloads; any tool that writes, triggers a run,
or mutates pipeline state; support for LLM backends other than NVIDIA NIM.

## Verification

`uv sync --extra dashboard --extra agent`; `uv run pytest tests/dashboard -q`;
manual: set `NVIDIA_API_KEY`, `streamlit run src/cybersec_slm/dashboard/app.py`,
ask a pipeline-status question and a corpus-content question, confirm the
trace expander shows the actual tool calls; unset the key and confirm the page
shows setup instructions instead of erroring.
