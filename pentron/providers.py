#!/usr/bin/env python3
"""
PENTRON - providers.py
LLM provider abstraction so the analysis loop isn't hardwired to Ollama.
Every provider exposes the same send()/list_models() contract; send()
never raises — it returns a "[!] ..." string on failure, same contract
llm.py already relies on for ask_ollama().
"""

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass

import requests


@dataclass(frozen=True)
class ProviderResponse:
    text: str
    finish_reason: str = "unknown"
    truncated: bool = False

    def __str__(self) -> str:
        return self.text


class BaseProvider(ABC):
    def __init__(self, model: str, timeout: int = 600, **kwargs):
        self.model = model
        self.timeout = timeout

    @abstractmethod
    def send(
        self, messages: list, max_tokens: int = 8192, temperature: float = 0.7
    ) -> ProviderResponse:
        """Return text plus the provider's completion metadata."""

    @abstractmethod
    def list_models(self) -> list:
        """Return the list of model names/ids available for this provider."""


class OllamaProvider(BaseProvider):
    def __init__(self, model: str, timeout: int = 600, host: str = None, **kwargs):
        super().__init__(model, timeout, **kwargs)
        self.host = host or os.environ.get("OLLAMA_HOST", "localhost:11434")

    def send(
        self, messages: list, max_tokens: int = 8192, temperature: float = 0.7
    ) -> ProviderResponse:
        try:
            payload = {
                "model": self.model,
                "messages": messages,
                "stream": False,
                "options": {
                    "num_predict": max_tokens,
                    "num_ctx": 16384,
                    "temperature": temperature,
                    "top_p": 0.9,
                },
            }
            resp = requests.post(
                f"http://{self.host}/api/chat", json=payload, timeout=self.timeout
            )
            resp.raise_for_status()
            data = resp.json()
            response = data.get("message", {}).get("content", "").strip()
            reason = data.get("done_reason", "unknown")
            return ProviderResponse(
                response or "[!] Model returned empty response.",
                reason,
                reason == "length",
            )
        except requests.exceptions.ConnectionError:
            return ProviderResponse("[!] Cannot connect to Ollama. Is it running?")
        except requests.exceptions.Timeout:
            return ProviderResponse("[!] Ollama timed out.", "timeout", True)
        except requests.exceptions.HTTPError as e:
            return ProviderResponse(f"[!] Ollama HTTP error: {e}", "error")
        except Exception as e:
            return ProviderResponse(f"[!] Unexpected error: {e}", "error")

    def list_models(self) -> list:
        try:
            resp = requests.get(f"http://{self.host}/api/tags", timeout=10)
            resp.raise_for_status()
            return [m["name"] for m in resp.json().get("models", [])]
        except Exception:
            return []


class OpenAIProvider(BaseProvider):
    def __init__(
        self,
        model: str,
        timeout: int = 600,
        api_key: str = None,
        base_url: str = "https://api.openai.com/v1",
        **kwargs,
    ):
        super().__init__(model, timeout, **kwargs)
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.base_url = base_url.rstrip("/")

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def send(
        self, messages: list, max_tokens: int = 8192, temperature: float = 0.7
    ) -> ProviderResponse:
        try:
            payload = {
                "model": self.model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }
            resp = requests.post(
                f"{self.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            choice = data["choices"][0]
            content = choice["message"]["content"].strip()
            reason = choice.get("finish_reason", "unknown")
            return ProviderResponse(
                content or "[!] Model returned empty response.",
                reason,
                reason == "length",
            )
        except requests.exceptions.Timeout:
            return ProviderResponse("[!] OpenAI request timed out.", "timeout", True)
        except requests.exceptions.HTTPError as e:
            return ProviderResponse(f"[!] OpenAI HTTP error: {e}", "error")
        except Exception as e:
            return ProviderResponse(f"[!] Unexpected error: {e}", "error")

    def list_models(self) -> list:
        try:
            resp = requests.get(
                f"{self.base_url}/models", headers=self._headers(), timeout=10
            )
            resp.raise_for_status()
            return [m["id"] for m in resp.json().get("data", [])]
        except Exception:
            return []


class AnthropicProvider(BaseProvider):
    API_VERSION = "2023-06-01"

    def __init__(self, model: str, timeout: int = 600, api_key: str = None, **kwargs):
        super().__init__(model, timeout, **kwargs)
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")

    def _headers(self) -> dict:
        return {
            "x-api-key": self.api_key,
            "anthropic-version": self.API_VERSION,
            "Content-Type": "application/json",
        }

    @staticmethod
    def _split_system(messages: list):
        system_text = ""
        rest = []
        for m in messages:
            if m.get("role") == "system":
                system_text = (system_text + "\n" + m["content"]).strip()
            else:
                rest.append(m)
        return system_text, rest

    def send(
        self, messages: list, max_tokens: int = 8192, temperature: float = 0.7
    ) -> ProviderResponse:
        try:
            system_text, rest = self._split_system(messages)
            payload = {
                "model": self.model,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "messages": rest,
            }
            if system_text:
                payload["system"] = system_text
            resp = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers=self._headers(),
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            blocks = data.get("content", [])
            text = "".join(b.get("text", "") for b in blocks).strip()
            reason = data.get("stop_reason", "unknown")
            return ProviderResponse(
                text or "[!] Model returned empty response.",
                reason,
                reason == "max_tokens",
            )
        except requests.exceptions.Timeout:
            return ProviderResponse("[!] Anthropic request timed out.", "timeout", True)
        except requests.exceptions.HTTPError as e:
            return ProviderResponse(f"[!] Anthropic HTTP error: {e}", "error")
        except Exception as e:
            return ProviderResponse(f"[!] Unexpected error: {e}", "error")

    def list_models(self) -> list:
        try:
            resp = requests.get(
                "https://api.anthropic.com/v1/models",
                headers=self._headers(),
                timeout=10,
            )
            resp.raise_for_status()
            return [m["id"] for m in resp.json().get("data", [])]
        except Exception:
            # /v1/models isn't available on all API versions/keys — fall back
            # to a static list rather than leaving the settings screen empty.
            return ["claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5-20251001"]


class GoogleProvider(BaseProvider):
    def __init__(self, model: str, timeout: int = 600, api_key: str = None, **kwargs):
        super().__init__(model, timeout, **kwargs)
        self.api_key = api_key or os.environ.get("GOOGLE_API_KEY", "")

    @staticmethod
    def _to_gemini_contents(messages: list):
        system_text = ""
        contents = []
        for m in messages:
            if m.get("role") == "system":
                system_text = (system_text + "\n" + m["content"]).strip()
            else:
                role = "model" if m.get("role") == "assistant" else "user"
                contents.append({"role": role, "parts": [{"text": m["content"]}]})
        return system_text, contents

    def send(
        self, messages: list, max_tokens: int = 8192, temperature: float = 0.7
    ) -> ProviderResponse:
        try:
            system_text, contents = self._to_gemini_contents(messages)
            payload = {
                "contents": contents,
                "generationConfig": {
                    "maxOutputTokens": max_tokens,
                    "temperature": temperature,
                },
            }
            if system_text:
                payload["systemInstruction"] = {"parts": [{"text": system_text}]}
            url = (
                f"https://generativelanguage.googleapis.com/v1beta/models/"
                f"{self.model}:generateContent?key={self.api_key}"
            )
            resp = requests.post(url, json=payload, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            candidate = data["candidates"][0]
            parts = candidate["content"]["parts"]
            text = "".join(p.get("text", "") for p in parts).strip()
            reason = candidate.get("finishReason", "unknown")
            return ProviderResponse(
                text or "[!] Model returned empty response.",
                reason,
                reason == "MAX_TOKENS",
            )
        except requests.exceptions.Timeout:
            return ProviderResponse("[!] Google request timed out.", "timeout", True)
        except requests.exceptions.HTTPError as e:
            return ProviderResponse(f"[!] Google HTTP error: {e}", "error")
        except Exception as e:
            return ProviderResponse(f"[!] Unexpected error: {e}", "error")

    def list_models(self) -> list:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models?key={self.api_key}"
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            return [
                m["name"].replace("models/", "") for m in resp.json().get("models", [])
            ]
        except Exception:
            return []


PROVIDERS = {
    "ollama": OllamaProvider,
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "google": GoogleProvider,
}


def get_provider(settings: dict = None) -> BaseProvider:
    """
    Build a provider from persisted settings (db.settings table), falling
    back to env vars for anything not set. Imports db lazily to avoid a
    hard dependency for callers that only need the provider classes.
    """
    if settings is None:
        try:
            from .db import get_settings

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
