import pytest

from pentron.ai.capabilities import (
    MODEL_CAPABILITIES,
    PROVIDER_CAPABILITIES,
    ContextPolicy,
    ModelCapabilities,
    ProviderCapabilities,
    context_policy_for,
    effective_capabilities,
)
from pentron.ai.providers.ollama import OllamaProvider


@pytest.mark.parametrize(
    ("factory", "args"),
    [
        (ModelCapabilities, (0, 1)),
        (ModelCapabilities, (100, 100)),
        (ProviderCapabilities, (0, 1)),
        (ProviderCapabilities, (100, 0)),
    ],
)
def test_invalid_capabilities_are_rejected(factory, args):
    with pytest.raises(ValueError):
        factory(*args)


def test_provider_and_model_capabilities_are_combined(monkeypatch):
    monkeypatch.setitem(
        PROVIDER_CAPABILITIES,
        "limited",
        ProviderCapabilities(4_096, 1_024, supports_tools=False),
    )
    monkeypatch.setitem(
        MODEL_CAPABILITIES,
        ("limited", "capable"),
        ModelCapabilities(8_192, 2_048, supports_tools=True),
    )

    capabilities = effective_capabilities("limited", "capable")

    assert capabilities.context_window == 4_096
    assert capabilities.max_output_tokens == 1_024
    assert capabilities.supports_tools is False


def test_known_default_model_keeps_its_configured_context():
    policy = context_policy_for("ollama", "huihui_ai/qwen3.5-abliterated:9b")

    assert policy.context_window == 16_384
    assert policy.max_output_tokens == 8_192
    assert policy.output_reserve == 2_000
    assert policy.input_budget == 13_360


def test_unknown_model_uses_conservative_deterministic_defaults():
    first = context_policy_for("openai", "unregistered-model")
    second = context_policy_for("openai", "unregistered-model")

    assert first == second
    assert first.context_window == 8_192
    assert first.max_output_tokens == 2_048
    assert first.capabilities.supports_tools is False
    assert first.capabilities.supports_structured_output is False


def test_context_policy_rejects_insufficient_and_excess_budgets():
    capabilities = ModelCapabilities(100, 50)

    with pytest.raises(ValueError, match="output limit"):
        ContextPolicy(capabilities, 51, 1, 0.75, 1, 1, 1)
    with pytest.raises(ValueError, match="no usable input budget"):
        ContextPolicy(ModelCapabilities(100, 99), 90, 10, 0.75, 0, 0, 0)
    with pytest.raises(ValueError, match="exceed"):
        ContextPolicy(capabilities, 20, 10, 0.75, 30, 30, 30)


def test_ollama_num_ctx_matches_resolved_model_limit(monkeypatch):
    request = {}

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"message": {"content": "ok"}, "done_reason": "stop"}

    def fake_post(url, **kwargs):
        request.update(kwargs["json"])
        return Response()

    monkeypatch.setattr("pentron.ai.providers.ollama.requests.post", fake_post)
    provider = OllamaProvider("huihui_ai/qwen3.5-abliterated:9b")

    provider.send([{"role": "user", "content": "hello"}], max_tokens=500)

    policy = context_policy_for(provider)
    assert request["options"]["num_ctx"] == policy.context_window
    assert request["options"]["num_ctx"] <= policy.capabilities.context_window


def test_ollama_output_is_capped_for_unknown_models(monkeypatch):
    request = {}

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"message": {"content": "ok"}, "done_reason": "stop"}

    def fake_post(url, **kwargs):
        request.update(kwargs["json"])
        return Response()

    monkeypatch.setattr("pentron.ai.providers.ollama.requests.post", fake_post)
    provider = OllamaProvider("unregistered-model")

    provider.send([{"role": "user", "content": "hello"}], max_tokens=8_192)

    assert (
        request["options"]["num_predict"]
        == context_policy_for(provider).max_output_tokens
    )
