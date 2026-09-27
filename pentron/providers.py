"""Temporary compatibility facade for :mod:`pentron.ai.providers`."""

from .ai.providers import (
    PROVIDERS,
    AnthropicProvider,
    BaseProvider,
    GoogleProvider,
    OllamaProvider,
    OpenAIProvider,
    ProviderResponse,
    get_provider,
)

__all__ = [
    "PROVIDERS",
    "AnthropicProvider",
    "BaseProvider",
    "GoogleProvider",
    "OllamaProvider",
    "OpenAIProvider",
    "ProviderResponse",
    "get_provider",
]
