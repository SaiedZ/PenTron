"""Parse and execute tool requests emitted by an analysis provider."""

import ipaddress
import socket
from urllib.parse import urlparse

from pydantic import ValidationError

from ...tools import registry
from ..capabilities import context_policy_for
from ..prompts import TOOL_OUTPUT_SYSTEM_PROMPT
from ..providers.factory import get_provider
from ..tool_calls import ToolCall, parse_fallback_tool_calls


def extract_tool_calls(response: str) -> list[ToolCall]:
    """Compatibility name for the structured fallback parser."""
    return parse_fallback_tool_calls(response)[0]


def _host(value: str) -> str:
    if "://" in value:
        return (urlparse(value).hostname or "").lower()
    return value.split("/")[0].split(":")[0].lower()


def _in_scope(value: str, session_target: str, allowed_subdomains: frozenset) -> bool:
    candidate = _host(value)
    if candidate == session_target.lower() or candidate in allowed_subdomains:
        return True
    try:
        ipaddress.ip_address(candidate)
        return candidate in {
            item[4][0] for item in socket.getaddrinfo(session_target, None)
        }
    except (ValueError, socket.gaierror):
        return False


def _audit(call, status: str, result: str, reason: str = "") -> dict:
    return {
        "call_type": "TOOL",
        "command": call.name,
        "arguments": call.arguments,
        "result": result,
        "status": status,
        "reason": reason,
        "blocked": status != "accepted",
    }


def _execute(call: ToolCall, session_target: str, allowed_subdomains: frozenset):
    spec = registry.find_by_command(call.name)
    if spec is None:
        reason = f"tool '{call.name}' is not registered or AI-dispatchable"
        return f"[!] REJECTED: {reason}", _audit(call, "rejected", "", reason)
    try:
        arguments = spec.argument_model.model_validate(call.arguments)
    except ValidationError as exc:
        reason = f"invalid arguments: {exc}"
        return f"[!] REJECTED: {reason}", _audit(call, "rejected", "", reason)
    target = arguments.target
    if not _in_scope(target, session_target, allowed_subdomains):
        reason = f"target '{target}' is outside authorized scope '{session_target}'"
        return f"[!] BLOCKED: {reason}", _audit(call, "blocked", "", reason)
    output = spec.runner(target)
    return output, _audit(call, "accepted", output.strip())


def summarize_tool_output(raw_output: str, provider=None) -> str:
    if len(raw_output) < 500:
        return raw_output

    try:
        provider = provider or get_provider()
        policy = context_policy_for(provider)
        summary = provider.send(
            [
                {"role": "system", "content": TOOL_OUTPUT_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": f"Compress this tool output:\n{raw_output[:6000]}",
                },
            ],
            max_tokens=min(512, policy.summary_budget),
            temperature=0.2,
        )
        text = summary.text
        return text if text and not text.startswith("[!]") else raw_output
    except Exception:
        return raw_output


def run_tool_calls(
    calls: list,
    session_target: str,
    provider=None,
    on_progress=None,
    allowed_subdomains: frozenset = frozenset(),
) -> tuple[str, list[dict]]:
    if not calls:
        return "", []

    results = ""
    records = []
    for raw_call in calls:
        try:
            call = ToolCall.model_validate(raw_call)
        except ValidationError as exc:
            call = ToolCall(name="invalid", arguments={})
            output = f"[!] REJECTED: malformed tool call: {exc}"
            record = _audit(call, "rejected", "", str(exc))
        else:
            print(f"\n  [DISPATCH] TOOL: {call.name} {call.arguments}")
            output, record = _execute(call, session_target, allowed_subdomains)

        blocked = record["blocked"]
        if on_progress and blocked:
            on_progress("call_blocked", f"TOOL: {call.name} -> {output.strip()}")

        compressed = summarize_tool_output(output.strip(), provider)
        results += f"\n[TOOL RESULT: {call.name}]\n"
        results += "─" * 40 + "\n" + compressed + "\n"
        records.append(record)

    return results, records
