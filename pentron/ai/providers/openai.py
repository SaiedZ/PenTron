"""OpenAI-compatible provider implementation."""

import os

import requests

from ..tool_calls import (
    RejectedToolCall,
    ToolCall,
    native_proposal_fields,
    normalize_native_tool_call,
)
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
        self,
        messages: list,
        max_tokens: int = 8192,
        temperature: float = 0.7,
        tools: list[dict] | None = None,
    ) -> ProviderResponse:
        try:
            payload = {
                "model": self.model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }
            if tools:
                payload["tools"] = [
                    {"type": "function", "function": tool} for tool in tools
                ]
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            choice = response.json()["choices"][0]
            message = choice["message"]
            text = (message.get("content") or "").strip()
            proposals = []
            for item in message.get("tool_calls", []):
                call_id, name, arguments = native_proposal_fields(
                    item, function_key="function"
                )
                proposals.append(
                    normalize_native_tool_call(
                        name,
                        arguments,
                        call_id=call_id,
                        json_arguments=True,
                    )
                )
            tool_calls = tuple(x for x in proposals if isinstance(x, ToolCall))
            rejected = tuple(x for x in proposals if isinstance(x, RejectedToolCall))
            reason = choice.get("finish_reason", "unknown")
            return ProviderResponse(
                text
                if text or tool_calls or rejected
                else "[!] Model returned empty response.",
                reason,
                reason == "length",
                tool_calls,
                rejected,
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
