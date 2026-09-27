"""Compatibility facade for :mod:`pentron.ai.providers`.

Deprecated internal import path. Application code should use
``pentron.ai.providers``. This module is kept temporarily for downstream callers
using the historical path.
"""

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
