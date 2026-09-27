import pytest

from pentron.ai.providers.anthropic import AnthropicProvider
from pentron.ai.providers.google import GoogleProvider
from pentron.ai.providers.ollama import OllamaProvider
from pentron.ai.providers.openai import OpenAIProvider
from pentron.ai.tool_calls import ToolCall


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self.payload


@pytest.mark.parametrize(
    ("provider", "module", "payload"),
    [
        (
            OpenAIProvider("model", api_key="key"),
            "pentron.ai.providers.openai.requests.post",
            {
                "choices": [
                    {
                        "message": {
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call-1",
                                    "function": {
                                        "name": "nmap",
                                        "arguments": '{"target":"example.test"}',
                                    },
                                }
                            ],
                        },
                        "finish_reason": "tool_calls",
                    }
                ]
            },
        ),
        (
            AnthropicProvider("model", api_key="key"),
            "pentron.ai.providers.anthropic.requests.post",
            {
                "content": [
                    {
                        "type": "tool_use",
                        "id": "call-1",
                        "name": "nmap",
                        "input": {"target": "example.test"},
                    }
                ],
                "stop_reason": "tool_use",
            },
        ),
        (
            GoogleProvider("model", api_key="key"),
            "pentron.ai.providers.google.requests.post",
            {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "functionCall": {
                                        "name": "nmap",
                                        "args": {"target": "example.test"},
                                    }
                                }
                            ]
                        },
                        "finishReason": "STOP",
                    }
                ]
            },
        ),
        (
            OllamaProvider("huihui_ai/qwen3.5-abliterated:9b"),
            "pentron.ai.providers.ollama.requests.post",
            {
                "message": {
                    "content": "",
                    "tool_calls": [
                        {
                            "function": {
                                "name": "nmap",
                                "arguments": {"target": "example.test"},
                            }
                        }
                    ],
                },
                "done_reason": "stop",
            },
        ),
    ],
)
def test_native_provider_calls_normalize_to_internal_contract(
    monkeypatch, provider, module, payload
):
    sent = {}

    def fake_post(*args, **kwargs):
        sent.update(kwargs["json"])
        return FakeResponse(payload)

    monkeypatch.setattr(module, fake_post)
    schema = {
        "name": "nmap",
        "description": "Run nmap.",
        "parameters": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
    }

    response = provider.send([], tools=[schema])

    assert response.tool_calls == (
        ToolCall(
            id="call-1" if provider.provider_name in {"openai", "anthropic"} else "",
            name="nmap",
            arguments={"target": "example.test"},
        ),
    )
    assert "tools" in sent


@pytest.mark.parametrize(
    "arguments",
    ["{not-json", '["wrong", "shape"]'],
)
def test_malformed_openai_tool_arguments_are_normalized_as_rejected(
    monkeypatch, arguments
):
    payload = {
        "choices": [
            {
                "message": {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "bad-call",
                            "function": {"name": "nmap", "arguments": arguments},
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ]
    }
    monkeypatch.setattr(
        "pentron.ai.providers.openai.requests.post",
        lambda *args, **kwargs: FakeResponse(payload),
    )

    response = OpenAIProvider("model", api_key="key").send([], tools=[])

    assert response.tool_calls == ()
    assert len(response.rejected_tool_calls) == 1
    assert response.rejected_tool_calls[0].name == "nmap"
    assert "invalid native tool proposal" in response.rejected_tool_calls[0].reason


@pytest.mark.parametrize(
    "proposal",
    ["not-an-object", {"function": "not-an-object"}, {"function": {}}],
)
def test_malformed_openai_tool_shapes_are_auditable(monkeypatch, proposal):
    payload = {
        "choices": [
            {
                "message": {"content": None, "tool_calls": [proposal]},
                "finish_reason": "tool_calls",
            }
        ]
    }
    monkeypatch.setattr(
        "pentron.ai.providers.openai.requests.post",
        lambda *args, **kwargs: FakeResponse(payload),
    )

    response = OpenAIProvider("model", api_key="key").send([], tools=[])

    assert response.tool_calls == ()
    assert len(response.rejected_tool_calls) == 1
    assert "invalid native tool proposal" in response.rejected_tool_calls[0].reason
