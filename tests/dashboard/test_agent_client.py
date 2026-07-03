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
