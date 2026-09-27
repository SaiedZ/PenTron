"""Anthropic provider implementation."""

import os

import requests

from ..tool_calls import (
    RejectedToolCall,
    ToolCall,
    native_proposal_fields,
    normalize_native_tool_call,
)
from .base import BaseProvider, ProviderResponse


class AnthropicProvider(BaseProvider):
    provider_name = "anthropic"
    API_VERSION = "2023-06-01"

    def __init__(
        self, model: str, timeout: int = 600, api_key: str | None = None, **kwargs
    ):
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
        for message in messages:
            if message.get("role") == "system":
                system_text = (system_text + "\n" + message["content"]).strip()
            else:
                rest.append(message)
        return system_text, rest

    def send(
        self,
        messages: list,
        max_tokens: int = 8192,
        temperature: float = 0.7,
        tools: list[dict] | None = None,
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
            if tools:
                payload["tools"] = [
                    {
                        "name": tool["name"],
                        "description": tool["description"],
                        "input_schema": tool["parameters"],
                    }
                    for tool in tools
                ]
            response = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers=self._headers(),
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
            text = "".join(block.get("text", "") for block in data.get("content", []))
            text = text.strip()
            proposals = []
            for block in data.get("content", []):
                if not isinstance(block, dict) or block.get("type") != "tool_use":
                    continue
                call_id, name, arguments = native_proposal_fields(block)
                proposals.append(
                    normalize_native_tool_call(name, arguments, call_id=call_id)
                )
            tool_calls = tuple(x for x in proposals if isinstance(x, ToolCall))
            rejected = tuple(x for x in proposals if isinstance(x, RejectedToolCall))
            reason = data.get("stop_reason", "unknown")
            return ProviderResponse(
                text
                if text or tool_calls or rejected
                else "[!] Model returned empty response.",
                reason,
                reason == "max_tokens",
                tool_calls,
                rejected,
            )
        except requests.exceptions.Timeout:
            return ProviderResponse("[!] Anthropic request timed out.", "timeout", True)
        except requests.exceptions.HTTPError as exc:
            return ProviderResponse(f"[!] Anthropic HTTP error: {exc}", "error")
        except Exception as exc:
            return ProviderResponse(f"[!] Unexpected error: {exc}", "error")

    def list_models(self) -> list:
        try:
            response = requests.get(
                "https://api.anthropic.com/v1/models",
                headers=self._headers(),
                timeout=10,
            )
            response.raise_for_status()
            return [model["id"] for model in response.json().get("data", [])]
        except Exception:
            return ["claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5-20251001"]
