"""LangGraph orchestration for bounded, stateful target analysis."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal, TypedDict

from langgraph.graph import END, START, StateGraph

from ..capabilities import ContextPolicy, context_policy_for
from ..providers.base import ProviderResponse
from ..tool_calls import RejectedToolCall, ToolCall, parse_fallback_tool_calls
from ..tool_registry import tool_schemas
from . import workflow as procedural
from .state import (
    AnalysisLimitReached,
    AnalysisState,
    DuplicateActionError,
    PendingAction,
)
from .validators import validate_or_repair_analysis

EvidenceDecision = Literal["sufficient", "investigate"]


class AnalysisGraphState(TypedDict):
    """Checkpoint-safe graph envelope containing the typed domain state."""

    analysis: AnalysisState
    response_text: str
    response_finish_reason: str
    response_truncated: bool
    dispatch_calls: list[dict]
    evidence_decision: EvidenceDecision


def _record_rejections(
    state: AnalysisState, rejected_proposals: list[RejectedToolCall]
) -> None:
    for rejected in rejected_proposals:
        action = PendingAction.from_rejected(rejected, state.iteration)
        try:
            state.queue(action)
        except DuplicateActionError:
            continue
        state.record_execution(action, status="rejected", reason=rejected.reason)


def _queue_new_calls(state: AnalysisState, calls: list[ToolCall]) -> list[ToolCall]:
    queued_ids: set[str] = set()
    queued_calls = []
    for call in calls:
        action = PendingAction.from_tool_call(call, state.iteration)
        if state.execution_for(action.id) or action.id in queued_ids:
            continue
        state.queue(action)
        queued_ids.add(action.id)
        queued_calls.append(call)
    return queued_calls


@dataclass
class AnalysisGraphNodes:
    """Independently testable node handlers and routing decisions."""

    provider: Any
    target: str
    allowed_subdomains: frozenset[str]
    max_iterations: int
    on_progress: Callable | None = None
    approval_gate: Any = None
    policy: ContextPolicy = field(init=False)

    def __post_init__(self) -> None:
        self.policy = context_policy_for(self.provider)

    def investigate(self, value: AnalysisGraphState) -> dict:
        state = value["analysis"]
        iteration = state.start_iteration()
        if self.on_progress:
            self.on_progress("ai_round_start", f"{iteration}/{self.max_iterations}")
        evidence = procedural._condense_recon(
            state.raw_scan, self.provider, self.policy
        )
        native_tools = (
            getattr(self.provider, "supports_native_tools", False)
            and self.policy.capabilities.supports_tools
        )
        response = self.provider.send(
            procedural._messages_for(state, evidence),
            max_tokens=self.policy.max_output_tokens,
            tools=tool_schemas() if native_tools else None,
        )
        if not isinstance(response, ProviderResponse):
            response = ProviderResponse(str(response))

        print(f"\n{'─' * 60}")
        print(f"[PENTRON - Round {iteration}]")
        print("─" * 60)
        print(response.text)

        rejected = list(response.rejected_tool_calls)
        if not native_tools:
            rejected.extend(
                RejectedToolCall(
                    id=call.id,
                    name=call.name,
                    arguments=call.arguments,
                    reason="native tool proposal rejected: native tools are disabled",
                )
                for call in response.tool_calls
            )
        _record_rejections(state, rejected)

        fallback_errors: list[str] = []
        if native_tools and response.tool_calls:
            proposed_calls = list(response.tool_calls)
        else:
            proposed_calls, fallback_errors = parse_fallback_tool_calls(response.text)
        _record_rejections(
            state,
            [
                RejectedToolCall(arguments={"error": error}, reason=error)
                for error in fallback_errors
            ],
        )
        dispatch_calls = _queue_new_calls(state, proposed_calls)
        if proposed_calls:
            state.transition_to("awaiting_actions")
        return {
            "analysis": state,
            "response_text": response.text,
            "response_finish_reason": response.finish_reason,
            "response_truncated": response.truncated,
            "dispatch_calls": [call.model_dump(mode="json") for call in dispatch_calls],
            "evidence_decision": ("investigate" if proposed_calls else "sufficient"),
        }

    def route_after_investigation(self, value: AnalysisGraphState) -> str:
        if value["dispatch_calls"]:
            return "execute_tools"
        if value["evidence_decision"] == "investigate":
            return "continue_or_limit"
        return "finalize"

    def execute_tools(self, value: AnalysisGraphState) -> dict:
        state = value["analysis"]
        calls = [ToolCall.model_validate(call) for call in value["dispatch_calls"]]
        pending = {action.id: action for action in state.pending_actions}
        approved_calls = []
        approved_action_ids = []
        for call in calls:
            action_id = PendingAction.from_tool_call(call, state.iteration).id
            action = pending[action_id]
            if self.approval_gate is None:
                approved = True
                reason = ""
            else:
                approved, reason = self.approval_gate.authorize(
                    action.id, action.name, action.arguments
                )
            if approved:
                approved_calls.append(call)
                approved_action_ids.append(action_id)
            else:
                state.record_execution(action, status="blocked", reason=reason)
        if self.on_progress:
            self.on_progress("tool_dispatch", approved_calls)
        try:
            tool_results, records = procedural.run_tool_calls(
                approved_calls,
                self.target,
                self.provider,
                self.on_progress,
                self.allowed_subdomains,
            )
        except Exception as exc:
            if self.approval_gate is not None:
                for action_id in approved_action_ids:
                    self.approval_gate.complete(
                        action_id, succeeded=False, reason=str(exc)
                    )
            raise
        if len(records) == 1 and not records[0].get("result"):
            records[0]["result"] = tool_results
        for action_id, record in zip(approved_action_ids, records, strict=True):
            state.record_execution(
                pending[action_id],
                status=record.get(
                    "status", "blocked" if record.get("blocked") else "accepted"
                ),
                result=record.get("result", ""),
                reason=record.get("reason", ""),
                call_type=record.get("call_type", "TOOL"),
            )
            if self.approval_gate is not None:
                succeeded = record.get("status") == "accepted"
                self.approval_gate.complete(
                    action_id,
                    succeeded=succeeded,
                    reason=""
                    if succeeded
                    else record.get("reason", "execution failed"),
                )
        procedural._refresh_evidence(state)
        return {"analysis": state, "dispatch_calls": []}

    def continue_or_limit(self, value: AnalysisGraphState) -> dict:
        state = value["analysis"]
        if state.iteration >= self.max_iterations:
            state.transition_to("failed")
            raise AnalysisLimitReached(state, self.max_iterations)
        return {"analysis": state}

    def route_after_limit_check(self, value: AnalysisGraphState) -> str:
        if value["analysis"].iteration < self.max_iterations:
            return "investigate"
        return "limit"

    def finalize(self, value: AnalysisGraphState) -> dict:
        state = value["analysis"]
        parsed, _ = validate_or_repair_analysis(
            self.provider,
            ProviderResponse(
                value["response_text"],
                value["response_finish_reason"],
                value["response_truncated"],
            ),
            max_tokens=self.policy.max_output_tokens,
            tool_calls=state.audit_records(),
        )
        state.hypotheses = parsed.hypotheses
        state.complete(parsed)
        return {"analysis": state}


def build_analysis_graph(
    *,
    provider,
    target: str,
    allowed_subdomains: frozenset,
    max_iterations: int,
    on_progress=None,
    approval_gate=None,
    checkpointer=None,
):
    """Compile the graph; durable checkpointing is deliberately opt-in."""
    nodes = AnalysisGraphNodes(
        provider=provider,
        target=target,
        allowed_subdomains=allowed_subdomains,
        max_iterations=max_iterations,
        on_progress=on_progress,
        approval_gate=approval_gate,
    )

    graph = StateGraph(AnalysisGraphState)
    graph.add_node("investigate", nodes.investigate)
    graph.add_node("execute_tools", nodes.execute_tools)
    graph.add_node("continue_or_limit", nodes.continue_or_limit)
    graph.add_node("finalize", nodes.finalize)
    graph.add_edge(START, "investigate")
    graph.add_conditional_edges(
        "investigate",
        nodes.route_after_investigation,
        {
            "execute_tools": "execute_tools",
            "continue_or_limit": "continue_or_limit",
            "finalize": "finalize",
        },
    )
    graph.add_edge("execute_tools", "continue_or_limit")
    graph.add_conditional_edges(
        "continue_or_limit",
        nodes.route_after_limit_check,
        {"investigate": "investigate", "limit": "continue_or_limit"},
    )
    graph.add_edge("finalize", END)
    return graph.compile(checkpointer=checkpointer)


def run_graph_analysis(
    state: AnalysisState,
    provider,
    *,
    target: str,
    allowed_subdomains: frozenset,
    max_iterations: int,
    on_progress=None,
    approval_gate=None,
    checkpointer=None,
    thread_id: str | None = None,
    resume_from_checkpoint: bool = False,
):
    if state.iteration >= max_iterations:
        raise AnalysisLimitReached(state, max_iterations)
    if checkpointer is not None and not thread_id:
        raise ValueError("thread_id is required when checkpointing is enabled")
    if resume_from_checkpoint and checkpointer is None:
        raise ValueError("a checkpointer is required to resume a graph thread")
    graph = build_analysis_graph(
        provider=provider,
        target=target,
        allowed_subdomains=allowed_subdomains,
        max_iterations=max_iterations,
        on_progress=on_progress,
        approval_gate=approval_gate,
        checkpointer=checkpointer,
    )
    config = (
        {"configurable": {"thread_id": thread_id}} if checkpointer is not None else None
    )
    graph_input = None
    if not resume_from_checkpoint:
        graph_input = {
            "analysis": state,
            "response_text": "",
            "response_finish_reason": "unknown",
            "response_truncated": False,
            "dispatch_calls": [],
            "evidence_decision": "sufficient",
        }
    result = graph.invoke(graph_input, config=config)
    return result["analysis"]
