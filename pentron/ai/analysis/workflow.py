"""Provider/tool orchestration for a complete target analysis."""

import re

from ..capabilities import ContextPolicy, context_policy_for
from ..evidence import (
    conflicts_from_observations,
    facts_from_observations,
    observations_from_raw,
)
from ..models import AnalysisResult
from ..prompts import FINAL_PROMPT, SYSTEM_PROMPT
from ..providers.base import ProviderResponse
from ..tool_calls import RejectedToolCall, parse_fallback_tool_calls
from ..tool_registry import tool_schemas
from .state import (
    AnalysisState,
    AnalysisStateError,
    DuplicateActionError,
    PendingAction,
)
from .tool_dispatch import run_tool_calls, summarize_tool_output
from .validators import validate_or_repair_analysis

MAX_TOOL_LOOPS = 9


def create_analysis_state(target: str, raw_scan: str) -> AnalysisState:
    observations = observations_from_raw(raw_scan)
    return AnalysisState(
        target=target,
        raw_scan=raw_scan,
        observations=observations,
        facts=facts_from_observations(observations),
        conflicts=conflicts_from_observations(observations),
    )


def _messages_for(state: AnalysisState, evidence: str) -> list[dict]:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT + "\n\n" + FINAL_PROMPT},
        {
            "role": "user",
            "content": f"""TARGET: {state.target}

RECON EVIDENCE:
{evidence}

Analyze this target completely. Use the supplied registered tools if needed.
When no more tools are needed, return the final JSON assessment.""",
        },
    ]
    for execution in state.executions:
        messages.extend(
            [
                {
                    "role": "assistant",
                    "content": (
                        f"Requested {execution.proposal.name} with "
                        f"{execution.proposal.arguments}."
                    ),
                },
                {
                    "role": "user",
                    "content": f"""[TOOL RESULTS]
{execution.result or execution.reason}

Continue your analysis with this recorded result.
If analysis is complete, return the final JSON assessment.""",
                },
            ]
        )
    return messages


def _refresh_evidence(state: AnalysisState) -> None:
    sections = [state.raw_scan.rstrip()]
    for index, execution in enumerate(state.executions, 1):
        if execution.status != "accepted" or not execution.result.strip():
            continue
        marker = f"[ AI TOOL {index}: {execution.proposal.name} OUTPUT ]"
        if marker in state.raw_scan:
            continue
        sections.append(
            "\n".join(["=" * 50, marker, "=" * 50, execution.result.strip()])
        )
    state.raw_scan = "\n".join(section for section in sections if section)
    observations = observations_from_raw(state.raw_scan)
    state.observations = observations
    state.facts = facts_from_observations(observations)
    state.conflicts = conflicts_from_observations(observations)


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
    state: AnalysisState | None = None,
) -> tuple[AnalysisResult, list[dict]]:
    state = state or create_analysis_state(target, raw_scan)
    if state.target != target:
        raise ValueError("analysis state target does not match requested target")
    if state.status == "completed":
        if state.final_result is None:  # guarded by AnalysisState validation
            raise ValueError("completed analysis state has no final result")
        return state.final_result, state.audit_records()
    if state.pending_actions:
        raise ValueError("cannot resume while actions remain pending")
    remaining_loops = max_tool_loops - state.iteration
    if remaining_loops <= 0:
        raise AnalysisStateError(
            f"analysis iteration limit reached ({state.iteration}/{max_tool_loops})"
        )
    policy = context_policy_for(provider)
    evidence = _condense_recon(state.raw_scan, provider, policy)
    messages = _messages_for(state, evidence)
    final_response = ProviderResponse("")

    for _ in range(remaining_loops):
        loop = state.start_iteration()
        if on_progress:
            on_progress("ai_round_start", f"{loop}/{max_tool_loops}")
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
        print(f"[PENTRON - Round {loop}]")
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
            action = PendingAction.from_rejected(rejected, state.iteration)
            try:
                state.queue(action)
            except DuplicateActionError:
                continue
            state.record_execution(action, status="rejected", reason=rejected.reason)

        fallback_errors: list[str] = []
        if native_tools and response.tool_calls:
            tool_calls = list(response.tool_calls)
        else:
            tool_calls, fallback_errors = parse_fallback_tool_calls(response.text)
        for error in fallback_errors:
            rejected = RejectedToolCall(arguments={"error": error}, reason=error)
            action = PendingAction.from_rejected(rejected, state.iteration)
            try:
                state.queue(action)
            except DuplicateActionError:
                continue
            state.record_execution(action, status="rejected", reason=error)
        if not tool_calls:
            print("\n[*] No tool calls. Analysis complete.")
            break

        new_calls = []
        actions = []
        duplicate_results = []
        queued_ids: set[str] = set()
        for call in tool_calls:
            action = PendingAction.from_tool_call(call, state.iteration)
            previous = state.execution_for(action.id)
            if previous:
                duplicate_results.append(previous.result or previous.reason)
                continue
            if action.id in queued_ids:
                continue
            state.queue(action)
            queued_ids.add(action.id)
            new_calls.append(call)
            actions.append(action)
        if not new_calls:
            state.transition_to("awaiting_actions")
            messages.append(
                {
                    "role": "user",
                    "content": "[ALREADY EXECUTED]\n"
                    + "\n".join(duplicate_results)
                    + "\nReturn the final assessment without repeating actions.",
                }
            )
            continue
        if on_progress:
            on_progress("tool_dispatch", new_calls)

        tool_results, records = run_tool_calls(
            new_calls, target, provider, on_progress, allowed_subdomains
        )
        for action, record in zip(actions, records, strict=True):
            state.record_execution(
                action,
                status=record.get(
                    "status", "blocked" if record.get("blocked") else "accepted"
                ),
                result=record.get("result", ""),
                reason=record.get("reason", ""),
                call_type=record.get("call_type", "TOOL"),
            )
        _refresh_evidence(state)
        state.transition_to("awaiting_actions")
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
        tool_calls=state.audit_records(),
    )
    state.hypotheses = parsed.hypotheses
    state.complete(parsed)
    return parsed, state.audit_records()
