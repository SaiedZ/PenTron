"""Provider/tool orchestration for a complete target analysis."""

import re

from ..capabilities import ContextPolicy, context_policy_for
from ..models import AnalysisResult
from ..prompts import FINAL_PROMPT, SYSTEM_PROMPT
from ..providers.base import ProviderResponse
from ..tool_calls import RejectedToolCall, parse_fallback_tool_calls
from ..tool_registry import tool_schemas
from .tool_dispatch import run_tool_calls, summarize_tool_output
from .validators import validate_or_repair_analysis

MAX_TOOL_LOOPS = 9


def _condense_recon(raw_scan: str, provider, policy: ContextPolicy) -> str:
    summary_threshold = policy.session_context_budget * 4
    if len(raw_scan) <= summary_threshold:
        return raw_scan
    sections = re.split(r"(?=\n={20,}\n\[ )", raw_scan)
    condensed = []
    for section in sections:
        if not section.strip():
            continue
        if len(section) <= summary_threshold:
            condensed.append(section.strip())
        else:
            condensed.append(summarize_tool_output(section, provider))
    return "\n\n".join(condensed)


def run_analysis_workflow(
    target: str,
    raw_scan: str,
    provider,
    on_progress=None,
    allowed_subdomains: frozenset = frozenset(),
    max_tool_loops: int = MAX_TOOL_LOOPS,
) -> tuple[AnalysisResult, list[dict]]:
    policy = context_policy_for(provider)
    evidence = _condense_recon(raw_scan, provider, policy)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT + "\n\n" + FINAL_PROMPT},
        {
            "role": "user",
            "content": f"""TARGET: {target}

RECON EVIDENCE:
{evidence}

Analyze this target completely. Use the supplied registered tools if needed.
When no more tools are needed, return the final JSON assessment.""",
        },
    ]
    final_response = ProviderResponse("")
    tool_call_records = []

    for loop in range(max_tool_loops):
        if on_progress:
            on_progress("ai_round_start", f"{loop + 1}/{max_tool_loops}")
        schemas = tool_schemas()
        native_tools = (
            getattr(provider, "supports_native_tools", False)
            and policy.capabilities.supports_tools
        )
        response = provider.send(
            messages,
            max_tokens=policy.max_output_tokens,
            tools=schemas if native_tools else None,
        )
        if not isinstance(response, ProviderResponse):
            response = ProviderResponse(str(response))

        print(f"\n{'─' * 60}")
        print(f"[PENTRON - Round {loop + 1}]")
        print("─" * 60)
        print(response.text)
        final_response = response

        rejected_proposals = list(response.rejected_tool_calls)
        if not native_tools:
            rejected_proposals.extend(
                RejectedToolCall(
                    id=call.id,
                    name=call.name,
                    arguments=call.arguments,
                    reason="native tool proposal rejected: native tools are disabled",
                )
                for call in response.tool_calls
            )
        for rejected in rejected_proposals:
            tool_call_records.append(
                {
                    "call_type": "TOOL",
                    "command": rejected.name,
                    "arguments": rejected.arguments,
                    "result": "",
                    "status": "rejected",
                    "reason": rejected.reason,
                    "blocked": True,
                }
            )

        fallback_errors = []
        if native_tools and response.tool_calls:
            tool_calls = list(response.tool_calls)
        else:
            tool_calls, fallback_errors = parse_fallback_tool_calls(response.text)
        for error in fallback_errors:
            tool_call_records.append(
                {
                    "call_type": "TOOL",
                    "command": "invalid",
                    "arguments": {},
                    "result": "",
                    "status": "rejected",
                    "reason": error,
                    "blocked": True,
                }
            )
        if not tool_calls:
            print("\n[*] No tool calls. Analysis complete.")
            break
        if on_progress:
            on_progress("tool_dispatch", tool_calls)

        tool_results, records = run_tool_calls(
            tool_calls, target, provider, on_progress, allowed_subdomains
        )
        tool_call_records.extend(records)
        messages.append(
            {
                "role": "assistant",
                "content": response.text or "Requested registered tool execution.",
            }
        )
        messages.append(
            {
                "role": "user",
                "content": f"""[TOOL RESULTS]
{tool_results}

Continue your analysis with this new information.
If analysis is complete, return the final JSON assessment.""",
            }
        )

    parsed, _ = validate_or_repair_analysis(
        provider,
        final_response,
        max_tokens=policy.max_output_tokens,
        tool_calls=tool_call_records,
    )
    return parsed, tool_call_records
