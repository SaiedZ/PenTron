"""Ollama provider implementation."""

import os

import requests

from .base import BaseProvider, ProviderResponse


class OllamaProvider(BaseProvider):
    def __init__(
        self, model: str, timeout: int = 600, host: str | None = None, **kwargs
    ):
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
            response = requests.post(
                f"http://{self.host}/api/chat", json=payload, timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            text = data.get("message", {}).get("content", "").strip()
            reason = data.get("done_reason", "unknown")
            return ProviderResponse(
                text or "[!] Model returned empty response.", reason, reason == "length"
            )
        except requests.exceptions.ConnectionError:
            return ProviderResponse("[!] Cannot connect to Ollama. Is it running?")
        except requests.exceptions.Timeout:
            return ProviderResponse("[!] Ollama timed out.", "timeout", True)
        except requests.exceptions.HTTPError as exc:
            return ProviderResponse(f"[!] Ollama HTTP error: {exc}", "error")
        except Exception as exc:
            return ProviderResponse(f"[!] Unexpected error: {exc}", "error")

    def list_models(self) -> list:
        try:
            response = requests.get(f"http://{self.host}/api/tags", timeout=10)
            response.raise_for_status()
            return [model["name"] for model in response.json().get("models", [])]
        except Exception:
            return []
