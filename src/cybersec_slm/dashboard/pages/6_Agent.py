#!/usr/bin/env python3
"""Agent page: ask questions about pipeline status and corpus content.

Read-only. All reads go through :mod:`cybersec_slm.dashboard.agent_client`,
which calls read-only tools over :mod:`cybersec_slm.dashboard.agent_tools`. The
agent can look things up, never trigger a run or write anything.
"""

from __future__ import annotations

import streamlit as st

from cybersec_slm.dashboard import agent_client, ui

ui.inject_css()
ui.app_header("Agent")
st.caption("Ask about pipeline status or the corpus. Read-only: it can look "
           "things up, not trigger a run or change anything.")

EXAMPLES = [
    "Is a run in progress right now?",
    "Did the EDA sufficiency gate pass, and why?",
    "Which sub-domains have the fewest records?",
    "Show me records about SQL injection.",
    "How many records were dropped as duplicates?",
]


def _ask(question: str) -> None:
    """Send one question through the agent and record the answer + trace."""
    st.session_state["agent_history"].append({"role": "user", "content": question})
    result = agent_client.ask(st.session_state["agent_history"])
    answer = (f"Sorry, something went wrong talking to the model: {result['error']}"
              if result["error"] else (result["answer"] or "(no answer)"))
    st.session_state["agent_history"].append({"role": "assistant", "content": answer})
    if result["trace"]:
        st.session_state["agent_traces"][len(st.session_state["agent_history"]) - 1] = \
            result["trace"]


if not agent_client.is_available():
    st.info(
        "Not configured yet. Install the optional extra and set an API key:\n\n"
        "```bash\n"
        "uv sync --extra dashboard --extra agent\n"
        "export NVIDIA_API_KEY=...   # from build.nvidia.com\n"
        "```"
    )
else:
    st.session_state.setdefault("agent_history", [])
    st.session_state.setdefault("agent_traces", {})

    # Example prompts and a reset, shown above the transcript.
    top = st.columns([5, 1])
    top[0].markdown("**Try one of these**")
    if top[1].button("Clear chat", use_container_width=True,
                     disabled=not st.session_state["agent_history"]):
        st.session_state["agent_history"] = []
        st.session_state["agent_traces"] = {}
        st.rerun()

    pending: str | None = None
    ex_cols = st.columns(len(EXAMPLES))
    for col, ex in zip(ex_cols, EXAMPLES, strict=True):
        if col.button(ex, use_container_width=True, key=f"ex_{ex}"):
            pending = ex
    st.divider()

    for i, msg in enumerate(st.session_state["agent_history"]):
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            trace = st.session_state["agent_traces"].get(i)
            if trace:
                with st.expander("what I looked up"):
                    for call in trace:
                        st.markdown(f"**{call['tool']}**`({call['args']})`")
                        st.json(call["result"])

    typed = st.chat_input("Ask a question...")
    question = typed or pending
    if question:
        _ask(question)
        st.rerun()
