import json

import pytest

from api.routers.pages import render_safe_markdown
from pentron.ai.analysis import AnalysisIncompleteError, analyse_target
from pentron.ai.providers import ProviderResponse


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
            ProviderResponse("[TOOL: nmap -sV example.test]", "stop"),
            ProviderResponse(valid_result(), "stop"),
        ]
    )
    dispatched = []

    def fake_run(calls, *args):
        dispatched.append(calls)
        return "mock tool evidence", [{"command": calls[0][1], "blocked": False}]

    monkeypatch.setattr("pentron.ai.analysis.workflow.run_tool_calls", fake_run)

    result = analyse_target("example.test", "short evidence", provider=provider)

    assert dispatched == [[("TOOL", "nmap -sV example.test")]]
    assert result["tool_calls"][0]["blocked"] is False
    assert "mock tool evidence" in provider.calls[1][0][-1]["content"]


def test_multiple_tool_rounds_are_supported(monkeypatch):
    provider = FakeProvider(
        [
            ProviderResponse("[SEARCH: first query]", "stop"),
            ProviderResponse("[SEARCH: second query]", "stop"),
            ProviderResponse(valid_result(), "stop"),
        ]
    )
    monkeypatch.setattr(
        "pentron.ai.analysis.workflow.run_tool_calls",
        lambda calls, *args: (
            f"result for {calls[0][1]}",
            [{"command": calls[0][1], "blocked": False}],
        ),
    )

    result = analyse_target("example.test", "short evidence", provider=provider)

    assert len(provider.calls) == 3
    assert [record["command"] for record in result["tool_calls"]] == [
        "first query",
        "second query",
    ]


def test_out_of_scope_tool_is_recorded_as_blocked(monkeypatch):
    from pentron.ai.analysis.tool_dispatch import run_tool_calls

    monkeypatch.setattr(
        "pentron.ai.analysis.tool_dispatch.run_tool_by_command",
        lambda *args: "[!] BLOCKED: target outside authorized scope",
    )

    _, records = run_tool_calls([("TOOL", "nmap attacker.example")], "example.test")

    assert records[0]["blocked"] is True


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
