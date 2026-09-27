"""Parse and execute tool requests emitted by an analysis provider."""

import re

from ...search import handle_search_dispatch
from ...tools import run_tool_by_command
from ..prompts import TOOL_OUTPUT_SYSTEM_PROMPT
from ..providers.factory import get_provider


def extract_tool_calls(response: str) -> list[tuple[str, str]]:
    calls = []
    for match in re.findall(r"\[TOOL:\s*(.+?)\]", response):
        calls.append(("TOOL", match.strip()))
    for match in re.findall(r"\[SEARCH:\s*(.+?)\]", response):
        calls.append(("SEARCH", match.strip()))
    return calls


def summarize_tool_output(raw_output: str, provider=None) -> str:
    if len(raw_output) < 500:
        return raw_output

    try:
        provider = provider or get_provider()
        summary = provider.send(
            [
                {"role": "system", "content": TOOL_OUTPUT_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": f"Compress this tool output:\n{raw_output[:6000]}",
                },
            ],
            max_tokens=512,
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
    for call_type, call_content in calls:
        print(f"\n  [DISPATCH] {call_type}: {call_content}")
        if call_type == "TOOL":
            output = run_tool_by_command(
                call_content, session_target, allowed_subdomains
            )
        elif call_type == "SEARCH":
            output = handle_search_dispatch(call_content)
        else:
            output = f"[!] Unknown call type: {call_type}"

        blocked = output.strip().startswith("[!] BLOCKED:")
        if on_progress and blocked:
            on_progress(
                "call_blocked", f"{call_type}: {call_content} -> {output.strip()}"
            )

        compressed = summarize_tool_output(output.strip(), provider)
        results += f"\n[{call_type} RESULT: {call_content}]\n"
        results += "─" * 40 + "\n" + compressed + "\n"
        records.append(
            {
                "call_type": call_type,
                "command": call_content,
                "result": output.strip(),
                "blocked": blocked,
            }
        )

    return results, records
