"""Ollama provider implementation."""

import os

import requests

from ..capabilities import context_policy_for
from ..tool_calls import (
    RejectedToolCall,
    ToolCall,
    native_proposal_fields,
    normalize_native_tool_call,
)
from .base import BaseProvider, ProviderResponse


class OllamaProvider(BaseProvider):
    provider_name = "ollama"

    def __init__(
        self, model: str, timeout: int = 600, host: str | None = None, **kwargs
    ):
        super().__init__(model, timeout, **kwargs)
        self.host = host or os.environ.get("OLLAMA_HOST", "localhost:11434")

    def send(
        self,
        messages: list,
        max_tokens: int = 8192,
        temperature: float = 0.7,
        tools: list[dict] | None = None,
    ) -> ProviderResponse:
        try:
            policy = context_policy_for(self)
            payload = {
                "model": self.model,
                "messages": messages,
                "stream": False,
                "options": {
                    "num_predict": min(max(1, max_tokens), policy.max_output_tokens),
                    "num_ctx": policy.context_window,
                    "temperature": temperature,
                    "top_p": 0.9,
                },
            }
            if tools:
                payload["tools"] = [
                    {"type": "function", "function": tool} for tool in tools
                ]
            response = requests.post(
                f"http://{self.host}/api/chat", json=payload, timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            message = data.get("message", {})
            text = message.get("content", "").strip()
            proposals = []
            for item in message.get("tool_calls", []):
                call_id, name, arguments = native_proposal_fields(
                    item, function_key="function"
                )
                proposals.append(
                    normalize_native_tool_call(name, arguments, call_id=call_id)
                )
            tool_calls = tuple(x for x in proposals if isinstance(x, ToolCall))
            rejected = tuple(x for x in proposals if isinstance(x, RejectedToolCall))
            reason = data.get("done_reason", "unknown")
            return ProviderResponse(
                text
                if text or tool_calls or rejected
                else "[!] Model returned empty response.",
                reason,
                reason == "length",
                tool_calls,
                rejected,
                data.get("prompt_eval_count"),
                data.get("eval_count"),
                "provider"
                if data.get("prompt_eval_count") is not None
                or data.get("eval_count") is not None
                else "unavailable",
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
