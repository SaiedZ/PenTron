"""OpenAI-compatible provider implementation."""

import os

import requests

from .base import BaseProvider, ProviderResponse


class OpenAIProvider(BaseProvider):
    provider_name = "openai"

    def __init__(
        self,
        model: str,
        timeout: int = 600,
        api_key: str | None = None,
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
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            choice = response.json()["choices"][0]
            text = choice["message"]["content"].strip()
            reason = choice.get("finish_reason", "unknown")
            return ProviderResponse(
                text or "[!] Model returned empty response.", reason, reason == "length"
            )
        except requests.exceptions.Timeout:
            return ProviderResponse("[!] OpenAI request timed out.", "timeout", True)
        except requests.exceptions.HTTPError as exc:
            return ProviderResponse(f"[!] OpenAI HTTP error: {exc}", "error")
        except Exception as exc:
            return ProviderResponse(f"[!] Unexpected error: {exc}", "error")

    def list_models(self) -> list:
        try:
            response = requests.get(
                f"{self.base_url}/models", headers=self._headers(), timeout=10
            )
            response.raise_for_status()
            return [model["id"] for model in response.json().get("data", [])]
        except Exception:
            return []
