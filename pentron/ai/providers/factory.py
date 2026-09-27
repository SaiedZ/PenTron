"""Provider construction isolated from provider implementations."""

import os

from .base import BaseProvider


def get_provider(settings: dict | None = None) -> BaseProvider:
    from ...providers import PROVIDERS, OllamaProvider

    if settings is None:
        try:
            from ...db import get_settings

            settings = get_settings()
        except Exception:
            settings = {}

    name = (
        settings.get("provider") or os.environ.get("LLM_PROVIDER") or "ollama"
    ).lower()
    provider_cls = PROVIDERS.get(name, OllamaProvider)
    model = settings.get("model") or os.environ.get(
        "PENTRON_MODEL", "huihui_ai/qwen3.5-abliterated:9b"
    )
    timeout = int(
        settings.get("ollama_timeout") or os.environ.get("PENTRON_OLLAMA_TIMEOUT", 600)
    )

    kwargs = {}
    if name == "ollama":
        kwargs["host"] = settings.get("ollama_host") or os.environ.get(
            "OLLAMA_HOST", "localhost:11434"
        )
    else:
        kwargs["api_key"] = settings.get("api_key")

    return provider_cls(model=model, timeout=timeout, **kwargs)
