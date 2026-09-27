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


class RejectedToolCall(BaseModel):
    """Native proposal that could not satisfy the normalized contract."""

    model_config = ConfigDict(extra="forbid")

    id: str = ""
    name: str = "invalid"
    arguments: Any = None
    reason: str


def normalize_native_tool_call(
    name: Any, arguments: Any, *, call_id: Any = "", json_arguments: bool = False
) -> ToolCall | RejectedToolCall:
    """Normalize provider payloads without losing malformed proposals to audit."""
    raw_arguments = arguments
    try:
        if json_arguments:
            arguments = json.loads(arguments or "{}")
        return ToolCall.model_validate(
            {"id": call_id or "", "name": name, "arguments": arguments}
        )
    except (json.JSONDecodeError, ValidationError, TypeError) as exc:
        return RejectedToolCall(
            id=str(call_id or ""),
            name=str(name or "invalid"),
            arguments=raw_arguments,
            reason=f"invalid native tool proposal: {exc}",
        )


def native_proposal_fields(
    proposal: Any, *, function_key: str | None = None
) -> tuple[Any, Any, Any]:
    """Safely extract id, name, and arguments from provider-native payloads."""
    if not isinstance(proposal, dict):
        return "", None, proposal
    function = proposal.get(function_key) if function_key else proposal
    if not isinstance(function, dict):
        return proposal.get("id", ""), None, function
    arguments_key = "input" if function_key is None else "arguments"
    return (
        proposal.get("id", ""),
        function.get("name"),
        function.get(arguments_key),
    )


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
