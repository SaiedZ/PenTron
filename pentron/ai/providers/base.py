"""Common contracts implemented by every LLM provider."""

from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..tool_calls import RejectedToolCall, ToolCall


@dataclass(frozen=True)
class ProviderResponse:
    text: str
    finish_reason: str = "unknown"
    truncated: bool = False
    tool_calls: tuple[ToolCall, ...] = ()
    rejected_tool_calls: tuple[RejectedToolCall, ...] = ()

    def __str__(self) -> str:
        return self.text


class BaseProvider(ABC):
    provider_name = "unknown"
    supports_native_tools = True

    def __init__(self, model: str, timeout: int = 600, **kwargs):
        self.model = model
        self.timeout = timeout

    @abstractmethod
    def send(
        self,
        messages: list,
        max_tokens: int = 8192,
        temperature: float = 0.7,
        tools: list[dict] | None = None,
    ) -> ProviderResponse:
        """Return text plus the provider's completion metadata."""

    @abstractmethod
    def list_models(self) -> list:
        """Return the model names or IDs available for this provider."""
