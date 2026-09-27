import json

import pytest

from api.routers.pages import render_safe_markdown
from pentron.ai.analysis import AnalysisIncompleteError, analyse_target
from pentron.ai.capabilities import context_policy_for
from pentron.ai.providers import ProviderResponse
from pentron.ai.tool_calls import RejectedToolCall, ToolCall


def valid_result(**overrides):
    data = {
        "risk_level": "LOW",
        "short_summary": "No material weakness was confirmed.",
        "analysis_markdown": "## Assessment\n\nNo confirmed findings.",
        "vulnerabilities": [],
        "exploit_suggestions": [],
    }
    data.update(overrides)
    return json.dumps(data)


class FakeProvider:
    provider_name = "ollama"
    model = "huihui_ai/qwen3.5-abliterated:9b"
    supports_native_tools = True

    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def send(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        return next(self.responses)


def test_valid_json_is_structured():
    provider = FakeProvider([ProviderResponse(valid_result(), "stop")])

    result = analyse_target("example.test", "short evidence", provider=provider)

    assert result["risk_level"] == "LOW"
    assert result["summary"].startswith("No material")
    assert result["vulnerabilities"] == []
    assert len(provider.calls) == 1


def test_analysis_uses_the_resolved_provider_model_policy():
    provider = FakeProvider([ProviderResponse(valid_result(), "stop")])
    provider.provider_name = "ollama"
    provider.model = "huihui_ai/qwen3.5-abliterated:9b"

    analyse_target("example.test", "short evidence", provider=provider)

    assert (
        provider.calls[0][1]["max_tokens"]
        == context_policy_for(provider).max_output_tokens
    )


def test_invalid_json_is_repaired_once():
    provider = FakeProvider(
        [ProviderResponse("not json", "stop"), ProviderResponse(valid_result(), "stop")]
    )

    result = analyse_target("example.test", "short evidence", provider=provider)

    assert result["risk_level"] == "LOW"
    assert len(provider.calls) == 2


def test_truncated_then_invalid_becomes_partial():
    provider = FakeProvider(
        [
            ProviderResponse('{"risk_level":', "length", True),
            ProviderResponse("still invalid", "stop"),
        ]
    )

    with pytest.raises(AnalysisIncompleteError) as exc_info:
        analyse_target("example.test", "short evidence", provider=provider)

    assert "remained invalid" in str(exc_info.value)
    assert len(provider.calls) == 2


def test_one_tool_call_is_reinjected_before_final_result(monkeypatch):
    provider = FakeProvider(
        [
            ProviderResponse(
                "",
                "tool_calls",
                tool_calls=(
                    ToolCall(name="nmap", arguments={"target": "example.test"}),
                ),
            ),
            ProviderResponse(valid_result(), "stop"),
        ]
    )
    dispatched = []

    def fake_run(calls, *args):
        dispatched.append(calls)
        return "mock tool evidence", [{"command": calls[0].name, "blocked": False}]

    monkeypatch.setattr("pentron.ai.analysis.workflow.run_tool_calls", fake_run)

    result = analyse_target("example.test", "short evidence", provider=provider)

    assert dispatched == [[ToolCall(name="nmap", arguments={"target": "example.test"})]]
    assert result["tool_calls"][0]["blocked"] is False
    assert "mock tool evidence" in provider.calls[1][0][-1]["content"]


def test_multiple_tool_rounds_are_supported(monkeypatch):
    provider = FakeProvider(
        [
            ProviderResponse(
                '<tool_call>{"name":"nmap","arguments":'
                '{"target":"example.test"}}</tool_call>',
                "stop",
            ),
            ProviderResponse(
                '<tool_call>{"name":"whois","arguments":'
                '{"target":"example.test"}}</tool_call>',
                "stop",
            ),
            ProviderResponse(valid_result(), "stop"),
        ]
    )
    monkeypatch.setattr(
        "pentron.ai.analysis.workflow.run_tool_calls",
        lambda calls, *args: (
            f"result for {calls[0].name}",
            [{"command": calls[0].name, "blocked": False}],
        ),
    )

    result = analyse_target("example.test", "short evidence", provider=provider)

    assert len(provider.calls) == 3
    assert [record["command"] for record in result["tool_calls"]] == [
        "nmap",
        "whois",
    ]


def test_out_of_scope_tool_is_recorded_as_blocked(monkeypatch):
    from pentron.ai.analysis.tool_dispatch import run_tool_calls

    _, records = run_tool_calls(
        [ToolCall(name="nmap", arguments={"target": "attacker.example"})],
        "example.test",
    )

    assert records[0]["blocked"] is True


def test_rejected_native_proposal_is_audited_without_executor_call(monkeypatch):
    provider = FakeProvider(
        [
            ProviderResponse(
                valid_result(),
                "stop",
                rejected_tool_calls=(
                    RejectedToolCall(
                        name="nmap",
                        arguments='["wrong"]',
                        reason="invalid native tool proposal",
                    ),
                ),
            )
        ]
    )
    executor_calls = []
    monkeypatch.setattr(
        "pentron.ai.analysis.workflow.run_tool_calls",
        lambda *args: executor_calls.append(args) or ("", []),
    )

    result = analyse_target("example.test", "short evidence", provider=provider)

    assert executor_calls == []
    assert result["tool_calls"][0]["status"] == "rejected"
    assert result["tool_calls"][0]["command"] == "nmap"


def test_native_schemas_require_provider_and_effective_model_support():
    known = FakeProvider([ProviderResponse(valid_result(), "stop")])
    known.provider_name = "ollama"
    known.model = "huihui_ai/qwen3.5-abliterated:9b"
    known.supports_native_tools = True
    analyse_target("example.test", "short evidence", provider=known)
    assert known.calls[0][1]["tools"]

    unknown = FakeProvider([ProviderResponse(valid_result(), "stop")])
    unknown.provider_name = "ollama"
    unknown.model = "unknown-model"
    unknown.supports_native_tools = True
    analyse_target("example.test", "short evidence", provider=unknown)
    assert unknown.calls[0][1]["tools"] is None

    unsupported = FakeProvider([ProviderResponse(valid_result(), "stop")])
    unsupported.provider_name = "ollama"
    unsupported.model = "huihui_ai/qwen3.5-abliterated:9b"
    unsupported.supports_native_tools = False
    analyse_target("example.test", "short evidence", provider=unsupported)
    assert unsupported.calls[0][1]["tools"] is None


def test_native_proposal_is_rejected_when_effective_policy_disables_tools(
    monkeypatch,
):
    provider = FakeProvider(
        [
            ProviderResponse(
                valid_result(),
                "tool_calls",
                tool_calls=(
                    ToolCall(name="nmap", arguments={"target": "example.test"}),
                ),
            )
        ]
    )
    provider.provider_name = "ollama"
    provider.model = "unknown-model"
    provider.supports_native_tools = True
    executor_calls = []
    monkeypatch.setattr(
        "pentron.ai.analysis.workflow.run_tool_calls",
        lambda *args: executor_calls.append(args) or ("", []),
    )

    result = analyse_target("example.test", "short evidence", provider=provider)

    assert provider.calls[0][1]["tools"] is None
    assert executor_calls == []
    assert result["tool_calls"][0]["status"] == "rejected"
    assert "native tools are disabled" in result["tool_calls"][0]["reason"]


def test_markdown_renderer_disables_raw_html_and_unsafe_links():
    rendered = str(
        render_safe_markdown(
            "## Safe\n<script>alert(1)</script>\n[x](javascript:alert(1))"
        )
    )

    assert "<h2>Safe</h2>" in rendered
    assert "<script>" not in rendered
    assert 'href="javascript:' not in rendered


def test_markdown_renderer_supports_tables():
    rendered = str(
        render_safe_markdown(
            "| Attribute | Value |\n"
            "|---|---|\n"
            "| Host | example.test |\n"
            "| IP | 192.0.2.1 |"
        )
    )

    assert "<table>" in rendered
    assert "<th>Attribute</th>" in rendered
    assert "<td>example.test</td>" in rendered
