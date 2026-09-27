"""Google Gemini provider implementation."""

import os

import requests

from ..tool_calls import ToolCall
from .base import BaseProvider, ProviderResponse


class GoogleProvider(BaseProvider):
    provider_name = "google"

    def __init__(
        self, model: str, timeout: int = 600, api_key: str | None = None, **kwargs
    ):
        super().__init__(model, timeout, **kwargs)
        self.api_key = api_key or os.environ.get("GOOGLE_API_KEY", "")

    @staticmethod
    def _to_gemini_contents(messages: list):
        system_text = ""
        contents = []
        for message in messages:
            if message.get("role") == "system":
                system_text = (system_text + "\n" + message["content"]).strip()
            else:
                role = "model" if message.get("role") == "assistant" else "user"
                contents.append({"role": role, "parts": [{"text": message["content"]}]})
        return system_text, contents

    def send(
        self,
        messages: list,
        max_tokens: int = 8192,
        temperature: float = 0.7,
        tools: list[dict] | None = None,
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
            if tools:
                payload["tools"] = [{"functionDeclarations": tools}]
            url = (
                "https://generativelanguage.googleapis.com/v1beta/models/"
                f"{self.model}:generateContent?key={self.api_key}"
            )
            response = requests.post(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            candidate = response.json()["candidates"][0]
            parts = candidate["content"]["parts"]
            text = "".join(part.get("text", "") for part in parts).strip()
            tool_calls = tuple(
                ToolCall(
                    name=part["functionCall"]["name"],
                    arguments=part["functionCall"].get("args", {}),
                )
                for part in parts
                if "functionCall" in part
            )
            reason = candidate.get("finishReason", "unknown")
            return ProviderResponse(
                text if text or tool_calls else "[!] Model returned empty response.",
                reason,
                reason == "MAX_TOKENS",
                tool_calls,
            )
        except requests.exceptions.Timeout:
            return ProviderResponse("[!] Google request timed out.", "timeout", True)
        except requests.exceptions.HTTPError as exc:
            return ProviderResponse(f"[!] Google HTTP error: {exc}", "error")
        except Exception as exc:
            return ProviderResponse(f"[!] Unexpected error: {exc}", "error")

    def list_models(self) -> list:
        try:
            url = (
                "https://generativelanguage.googleapis.com/v1beta/models"
                f"?key={self.api_key}"
            )
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return [
                model["name"].replace("models/", "")
                for model in response.json().get("models", [])
            ]
        except Exception:
            return []
