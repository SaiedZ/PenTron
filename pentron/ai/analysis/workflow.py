"""Provider/tool orchestration for a complete target analysis."""

import re

from ..models import AnalysisResult
from ..prompts import FINAL_PROMPT, SYSTEM_PROMPT
from ..providers.base import ProviderResponse
from .tool_dispatch import extract_tool_calls, run_tool_calls, summarize_tool_output
from .validators import validate_or_repair_analysis

MAX_TOKENS = 8192
MAX_TOOL_LOOPS = 9
SUMMARY_THRESHOLD = 4000


def _condense_recon(raw_scan: str, provider) -> str:
    if len(raw_scan) <= SUMMARY_THRESHOLD:
        return raw_scan
    sections = re.split(r"(?=\n={20,}\n\[ )", raw_scan)
    condensed = []
    for section in sections:
        if not section.strip():
            continue
        if len(section) <= SUMMARY_THRESHOLD:
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
    evidence = _condense_recon(raw_scan, provider)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT + "\n\n" + FINAL_PROMPT},
        {
            "role": "user",
            "content": f"""TARGET: {target}

RECON EVIDENCE:
{evidence}

Analyze this target completely. Use [TOOL:] or [SEARCH:] if you need more information.
When no more tools are needed, return the final JSON assessment.""",
        },
    ]
    final_response = ProviderResponse("")
    tool_call_records = []

    for loop in range(max_tool_loops):
        if on_progress:
            on_progress("ai_round_start", f"{loop + 1}/{max_tool_loops}")
        response = provider.send(messages, max_tokens=MAX_TOKENS)
        if not isinstance(response, ProviderResponse):
            response = ProviderResponse(str(response))

        print(f"\n{'─' * 60}")
        print(f"[PENTRON - Round {loop + 1}]")
        print("─" * 60)
        print(response.text)
        final_response = response

        tool_calls = extract_tool_calls(response.text)
        if not tool_calls:
            print("\n[*] No tool calls. Analysis complete.")
            break
        if on_progress:
            on_progress("tool_dispatch", tool_calls)

        tool_results, records = run_tool_calls(
            tool_calls, target, provider, on_progress, allowed_subdomains
        )
        tool_call_records.extend(records)
        messages.append({"role": "assistant", "content": response.text})
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
        max_tokens=MAX_TOKENS,
        tool_calls=tool_call_records,
    )
    return parsed, tool_call_records
