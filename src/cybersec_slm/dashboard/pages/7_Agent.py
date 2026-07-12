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
