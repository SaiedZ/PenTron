import pytest
from pydantic import ValidationError

from pentron.ai.analysis.tool_dispatch import run_tool_calls
from pentron.ai.tool_calls import ToolCall, parse_fallback_tool_calls
from pentron.tools import base, registry


def test_tool_call_rejects_extra_envelope_fields():
    with pytest.raises(ValidationError):
        ToolCall(name="nmap", arguments={"target": "example.test"}, shell="id")


def test_fallback_accepts_only_strict_json_envelope():
    calls, errors = parse_fallback_tool_calls(
        '<tool_call>{"name":"nmap","arguments":{"target":"example.test"}}</tool_call>'
    )
    assert not errors
    assert calls == [
        ToolCall(
            name="nmap",
            arguments={"target": "example.test"},
            source="fallback",
        )
    ]
    assert parse_fallback_tool_calls("[TOOL: nmap example.test]") == ([], [])
    assert parse_fallback_tool_calls("<tool_call>not-json</tool_call>")[1]


def test_registered_tool_executes_only_after_validation(monkeypatch):
    executed = []
    monkeypatch.setattr(
        base, "run_tool", lambda argv, **kwargs: executed.append(argv) or "ok"
    )

    _, records = run_tool_calls(
        [ToolCall(name="nmap", arguments={"target": "example.test"})],
        "example.test",
    )

    assert executed == [["nmap", "-sV", "-sC", "-T4", "--open", "example.test"]]
    assert records[0]["status"] == "accepted"


@pytest.mark.parametrize(
    ("call", "status"),
    [
        (
            ToolCall(name="not-registered", arguments={"target": "example.test"}),
            "rejected",
        ),
        (ToolCall(name="nmap", arguments={"target": "attacker.test"}), "blocked"),
        (
            ToolCall(name="nmap", arguments={"target": "example.test", "flags": "-A"}),
            "rejected",
        ),
    ],
)
def test_unauthorized_or_malformed_calls_never_execute(monkeypatch, call, status):
    executed = []
    monkeypatch.setattr(
        base, "run_tool", lambda argv, **kwargs: executed.append(argv) or "ok"
    )

    _, records = run_tool_calls([call], "example.test")

    assert executed == []
    assert records[0]["status"] == status
    assert records[0]["blocked"] is True


def test_provider_schema_is_derived_from_registry():
    schemas = registry.ai_tool_specs()
    assert {item["name"] for item in schemas} == registry.allowed_commands()
    assert all(item["parameters"]["additionalProperties"] is False for item in schemas)
