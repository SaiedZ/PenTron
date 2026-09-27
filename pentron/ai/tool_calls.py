"""Provider-neutral, validated tool-call contract."""

import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = ""
    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    arguments: dict[str, Any]
    source: Literal["native", "fallback"] = "native"


_FALLBACK_PATTERN = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.S)


def parse_fallback_tool_calls(text: str) -> tuple[list[ToolCall], list[str]]:
    """Parse strict JSON envelopes used by models without native tool APIs."""
    calls, errors = [], []
    payloads = _FALLBACK_PATTERN.findall(text)
    if "<tool_call" in text and not payloads:
        errors.append("malformed <tool_call> envelope")
    for payload in payloads:
        try:
            data = json.loads(payload)
            data["source"] = "fallback"
            calls.append(ToolCall.model_validate(data))
        except (json.JSONDecodeError, ValidationError, TypeError) as exc:
            errors.append(str(exc))
    return calls, errors
