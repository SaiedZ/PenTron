"""Model capabilities and deterministic context-budget resolution."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderCapabilities:
    """Limits and features imposed by a provider API."""

    max_context_window: int
    max_output_tokens: int
    supports_tools: bool = False
    supports_structured_output: bool = False

    def __post_init__(self) -> None:
        if self.max_context_window <= 0:
            raise ValueError("Provider context window must be positive.")
        if self.max_output_tokens <= 0:
            raise ValueError("Provider output limit must be positive.")


@dataclass(frozen=True)
class ModelCapabilities:
    """Limits and optional features advertised by one model."""

    context_window: int
    max_output_tokens: int
    supports_tools: bool = False
    supports_structured_output: bool = False

    def __post_init__(self) -> None:
        if self.context_window <= 0:
            raise ValueError("Model context window must be positive.")
        if self.max_output_tokens <= 0:
            raise ValueError("Model output limit must be positive.")
        if self.max_output_tokens >= self.context_window:
            raise ValueError(
                "Model output limit must be smaller than its context window."
            )


@dataclass(frozen=True)
class ContextPolicy:
    """Effective limits shared by all workflows for a provider/model pair."""

    capabilities: ModelCapabilities
    output_reserve: int
    safety_margin: int
    compression_threshold: float
    session_context_budget: int
    history_budget: int
    summary_budget: int

    def __post_init__(self) -> None:
        if self.output_reserve <= 0:
            raise ValueError("Output reserve must be positive.")
        if self.output_reserve > self.capabilities.max_output_tokens:
            raise ValueError("Output reserve exceeds the model output limit.")
        if self.safety_margin < 0:
            raise ValueError("Safety margin cannot be negative.")
        if not 0 < self.compression_threshold <= 1:
            raise ValueError("Compression threshold must be between 0 and 1.")
        if (
            min(
                self.session_context_budget,
                self.history_budget,
                self.summary_budget,
            )
            < 0
        ):
            raise ValueError("Context category budgets cannot be negative.")
        if self.input_budget <= 0:
            raise ValueError("Context window leaves no usable input budget.")
        category_total = (
            self.session_context_budget + self.history_budget + self.summary_budget
        )
        if category_total > self.input_budget:
            raise ValueError("Context category budgets exceed the input budget.")

    @property
    def context_window(self) -> int:
        return self.capabilities.context_window

    @property
    def max_output_tokens(self) -> int:
        return self.capabilities.max_output_tokens

    @property
    def input_budget(self) -> int:
        return self.context_window - self.output_reserve - self.safety_margin

    @property
    def compression_trigger_tokens(self) -> int:
        return int(self.input_budget * self.compression_threshold)


UNKNOWN_MODEL_CAPABILITIES = ModelCapabilities(
    context_window=8_192,
    max_output_tokens=2_048,
)

PROVIDER_CAPABILITIES = {
    "ollama": ProviderCapabilities(131_072, 32_768, True, True),
    "openai": ProviderCapabilities(1_000_000, 128_000, True, True),
    "anthropic": ProviderCapabilities(1_000_000, 128_000, True, True),
    "google": ProviderCapabilities(2_000_000, 128_000, True, True),
}

MODEL_CAPABILITIES = {
    ("ollama", "huihui_ai/qwen3.5-abliterated:9b"): ModelCapabilities(
        context_window=16_384,
        max_output_tokens=8_192,
        supports_tools=True,
        supports_structured_output=True,
    ),
    ("ollama", "pentron-qwen"): ModelCapabilities(
        context_window=16_384,
        max_output_tokens=8_192,
        supports_tools=True,
        supports_structured_output=True,
    ),
}


def _provider_name(provider: object | str) -> str:
    if isinstance(provider, str):
        return provider.strip().lower()
    explicit_name = getattr(provider, "provider_name", None)
    if isinstance(explicit_name, str) and explicit_name:
        return explicit_name.lower()
    class_name = provider.__class__.__name__.lower()
    return class_name.removesuffix("provider")


def effective_capabilities(
    provider: object | str, model: str | None = None
) -> ModelCapabilities:
    """Combine provider and model limits, disabling unsupported features."""
    provider_name = _provider_name(provider)
    raw_model = model if model is not None else getattr(provider, "model", "")
    model_name = raw_model if isinstance(raw_model, str) else ""
    model_capabilities = MODEL_CAPABILITIES.get(
        (provider_name, model_name), UNKNOWN_MODEL_CAPABILITIES
    )
    provider_capabilities = PROVIDER_CAPABILITIES.get(
        provider_name,
        ProviderCapabilities(
            UNKNOWN_MODEL_CAPABILITIES.context_window,
            UNKNOWN_MODEL_CAPABILITIES.max_output_tokens,
        ),
    )
    context_window = min(
        model_capabilities.context_window,
        provider_capabilities.max_context_window,
    )
    max_output_tokens = min(
        model_capabilities.max_output_tokens,
        provider_capabilities.max_output_tokens,
        context_window - 1,
    )
    return ModelCapabilities(
        context_window=context_window,
        max_output_tokens=max_output_tokens,
        supports_tools=(
            model_capabilities.supports_tools and provider_capabilities.supports_tools
        ),
        supports_structured_output=(
            model_capabilities.supports_structured_output
            and provider_capabilities.supports_structured_output
        ),
    )


def context_policy_for(
    provider: object | str, model: str | None = None
) -> ContextPolicy:
    """Return the deterministic policy for a provider/model combination."""
    capabilities = effective_capabilities(provider, model)
    output_reserve = min(2_000, capabilities.max_output_tokens)
    safety_margin = max(512, capabilities.context_window // 16)
    input_budget = capabilities.context_window - output_reserve - safety_margin
    if input_budget <= 0:
        raise ValueError(
            "Provider/model limits leave no input budget after output reserve "
            "and safety margin."
        )

    summary_budget = min(800, max(0, input_budget // 10))
    session_context_budget = input_budget * 40 // 100
    history_budget = input_budget - session_context_budget - summary_budget
    return ContextPolicy(
        capabilities=capabilities,
        output_reserve=output_reserve,
        safety_margin=safety_margin,
        compression_threshold=0.75,
        session_context_budget=session_context_budget,
        history_budget=history_budget,
        summary_budget=summary_budget,
    )
