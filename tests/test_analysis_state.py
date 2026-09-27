import json

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from pydantic import ValidationError

from pentron.ai.analysis.state import (
    AnalysisLimitReached,
    AnalysisState,
    AnalysisStateError,
    DuplicateActionError,
    PendingAction,
)
from pentron.ai.analysis.workflow import (
    create_analysis_state,
    run_analysis_workflow,
    run_procedural_analysis_workflow,
)
from pentron.ai.providers import ProviderResponse
from pentron.ai.tool_calls import ToolCall


def valid_result():
    return json.dumps(
        {
            "risk_level": "LOW",
            "short_summary": "No confirmed weakness.",
            "analysis_markdown": "## Assessment\n\nNo confirmed findings.",
            "vulnerabilities": [],
            "exploit_suggestions": [],
        }
    )


class FakeProvider:
    provider_name = "ollama"
    model = "huihui_ai/qwen3.5-abliterated:9b"
    supports_native_tools = True

    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def send(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        return next(self.responses)


def executed_state() -> AnalysisState:
    state = create_analysis_state(
        "example.test", "[ NMAP OUTPUT ]\nexample.test port 443 open"
    )
    state.start_iteration()
    action = PendingAction.from_tool_call(
        ToolCall(name="nmap", arguments={"target": "example.test"}),
        state.iteration,
    )
    state.queue(action)
    state.record_execution(
        action,
        status="accepted",
        result="example.test port 443 open tls",
    )
    state.transition_to("awaiting_actions")
    return state


def test_state_serialization_preserves_provenance_and_safe_defaults():
    state = executed_state()

    restored = AnalysisState.model_validate_json(state.model_dump_json())
    other = create_analysis_state("other.test", "other evidence")

    assert restored == state
    assert restored.executions[0].proposal_id == restored.executions[0].proposal.id
    assert restored.iteration == 1
    assert other.executions == []
    assert other.observations is not state.observations


def test_state_rejects_invalid_transitions_and_broken_references():
    state = create_analysis_state("example.test", "evidence")

    with pytest.raises(AnalysisStateError, match="invalid transition"):
        state.transition_to("completed")
    with pytest.raises(ValidationError, match="broken observations"):
        AnalysisState(
            target="example.test",
            raw_scan="evidence",
            facts=[
                {
                    "id": "fact-1",
                    "statement": "unsupported",
                    "observation_ids": ["missing"],
                    "confidence": 1,
                }
            ],
        )


def test_duplicate_action_is_detected_before_execution():
    state = executed_state()
    repeated = PendingAction.from_tool_call(
        ToolCall(name="nmap", arguments={"target": "example.test"}),
        state.iteration,
    )
    state.transition_to("running")

    with pytest.raises(DuplicateActionError, match="already proposed"):
        state.queue(repeated)

    assert len(state.executions) == 1


def test_workflow_records_multiple_iterations_and_collected_evidence(monkeypatch):
    state = create_analysis_state("example.test", "initial evidence")
    provider = FakeProvider(
        [
            ProviderResponse(
                "",
                "tool_calls",
                tool_calls=(
                    ToolCall(name="nmap", arguments={"target": "example.test"}),
                ),
            ),
            ProviderResponse(valid_result(), "stop"),
        ]
    )
    monkeypatch.setattr(
        "pentron.ai.analysis.workflow.run_tool_calls",
        lambda *args: (
            "example.test port 443 open",
            [
                {
                    "command": "nmap",
                    "arguments": {"target": "example.test"},
                    "result": "example.test port 443 open",
                    "status": "accepted",
                    "blocked": False,
                }
            ],
        ),
    )

    result, records = run_analysis_workflow(
        state.target, state.raw_scan, provider, state=state
    )

    assert result.risk_level == "LOW"
    assert state.status == "completed"
    assert state.iteration == 2
    assert len(state.executions) == 1
    assert records[0]["command"] == "nmap"
    assert any("port 443 open" in item.value for item in state.observations)


def test_identical_calls_in_one_response_are_dispatched_once(monkeypatch):
    call = ToolCall(name="nmap", arguments={"target": "example.test"})
    state = create_analysis_state("example.test", "initial evidence")
    provider = FakeProvider(
        [
            ProviderResponse("", "tool_calls", tool_calls=(call, call)),
            ProviderResponse(valid_result(), "stop"),
        ]
    )
    dispatched = []

    def fake_run(calls, *args):
        dispatched.append(calls)
        return (
            "result",
            [
                {
                    "command": "nmap",
                    "arguments": call.arguments,
                    "result": "result",
                    "status": "accepted",
                    "blocked": False,
                }
            ],
        )

    monkeypatch.setattr("pentron.ai.analysis.workflow.run_tool_calls", fake_run)

    run_analysis_workflow(state.target, state.raw_scan, provider, state=state)

    assert dispatched == [[call]]
    assert len(state.executions) == 1


def test_serialized_partial_state_resumes_without_rerunning_execution(monkeypatch):
    state = AnalysisState.model_validate_json(executed_state().model_dump_json())
    provider = FakeProvider([ProviderResponse(valid_result(), "stop")])
    executor_calls = []
    monkeypatch.setattr(
        "pentron.ai.analysis.workflow.run_tool_calls",
        lambda *args: executor_calls.append(args) or ("", []),
    )

    _, records = run_analysis_workflow(
        state.target, state.raw_scan, provider, state=state
    )

    assert executor_calls == []
    assert state.iteration == 2
    assert len(records) == 1
    assert "example.test port 443 open tls" in provider.calls[0][0][-1]["content"]


def test_resume_uses_remaining_global_iteration_budget(monkeypatch):
    state = AnalysisState.model_validate_json(executed_state().model_dump_json())
    provider = FakeProvider([ProviderResponse(valid_result(), "stop")])
    progress = []

    run_analysis_workflow(
        state.target,
        state.raw_scan,
        provider,
        on_progress=lambda event, value: progress.append((event, value)),
        max_tool_loops=2,
        state=state,
    )

    assert len(provider.calls) == 1
    assert state.iteration == 2
    assert ("ai_round_start", "2/2") in progress


def test_resume_with_exhausted_budget_fails_without_provider_call():
    state = AnalysisState.model_validate_json(executed_state().model_dump_json())
    provider = FakeProvider([])

    with pytest.raises(AnalysisStateError, match="iteration limit reached"):
        run_analysis_workflow(
            state.target,
            state.raw_scan,
            provider,
            max_tool_loops=1,
            state=state,
        )

    assert provider.calls == []
    assert state.status == "awaiting_actions"


def test_iteration_limit_exposes_inspectable_partial_state(monkeypatch):
    state = create_analysis_state("example.test", "initial evidence")
    provider = FakeProvider(
        [
            ProviderResponse(
                "",
                "tool_calls",
                tool_calls=(
                    ToolCall(name="nmap", arguments={"target": "example.test"}),
                ),
            )
        ]
    )
    monkeypatch.setattr(
        "pentron.ai.analysis.workflow.run_tool_calls",
        lambda *args: (
            "port 443 open",
            [
                {
                    "command": "nmap",
                    "result": "port 443 open",
                    "status": "accepted",
                    "blocked": False,
                }
            ],
        ),
    )

    with pytest.raises(AnalysisLimitReached) as exc_info:
        run_analysis_workflow(
            state.target,
            state.raw_scan,
            provider,
            max_tool_loops=1,
            state=state,
        )

    partial = exc_info.value.state
    assert partial.status == "failed"
    assert partial.iteration == 1
    assert partial.executions[0].result == "port 443 open"
    assert any("port 443 open" in item.value for item in partial.observations)


def test_checkpointing_is_explicit_and_requires_thread_id():
    state = create_analysis_state("example.test", "initial evidence")
    provider = FakeProvider([ProviderResponse(valid_result(), "stop")])

    with pytest.raises(ValueError, match="thread_id is required"):
        run_analysis_workflow(
            state.target,
            state.raw_scan,
            provider,
            state=state,
            checkpointer=InMemorySaver(),
        )


def test_checkpoint_resume_does_not_repeat_completed_tools(monkeypatch):
    checkpointer = InMemorySaver()
    state = create_analysis_state("example.test", "initial evidence")
    first_provider = FakeProvider(
        [
            ProviderResponse(
                "",
                "tool_calls",
                tool_calls=(
                    ToolCall(name="nmap", arguments={"target": "example.test"}),
                ),
            )
        ]
    )
    dispatched = []

    def fake_run(calls, *args):
        dispatched.extend(calls)
        return (
            "port 443 open",
            [
                {
                    "command": "nmap",
                    "result": "port 443 open",
                    "status": "accepted",
                    "blocked": False,
                }
            ],
        )

    monkeypatch.setattr("pentron.ai.analysis.workflow.run_tool_calls", fake_run)
    with pytest.raises(AnalysisLimitReached):
        run_analysis_workflow(
            state.target,
            state.raw_scan,
            first_provider,
            max_tool_loops=1,
            state=state,
            checkpointer=checkpointer,
            thread_id="analysis-1",
        )

    resumed, records = run_analysis_workflow(
        state.target,
        state.raw_scan,
        FakeProvider([ProviderResponse(valid_result(), "stop")]),
        max_tool_loops=2,
        state=state,
        checkpointer=checkpointer,
        thread_id="analysis-1",
        resume_from_checkpoint=True,
    )

    assert resumed.risk_level == "LOW"
    assert len(dispatched) == 1
    assert len(records) == 1


def test_graph_and_procedural_workflows_match_reference_fixture():
    graph_state = create_analysis_state("example.test", "initial evidence")
    procedural_state = create_analysis_state("example.test", "initial evidence")
    graph_provider = FakeProvider([ProviderResponse(valid_result(), "stop")])
    procedural_provider = FakeProvider([ProviderResponse(valid_result(), "stop")])

    graph_result, graph_records = run_analysis_workflow(
        graph_state.target,
        graph_state.raw_scan,
        graph_provider,
        state=graph_state,
    )
    procedural_result, procedural_records = run_procedural_analysis_workflow(
        procedural_state.target,
        procedural_state.raw_scan,
        procedural_provider,
        state=procedural_state,
    )

    assert graph_result == procedural_result
    assert graph_records == procedural_records
    assert graph_state.iteration == procedural_state.iteration == 1


def test_graph_and_procedural_workflows_make_same_tool_decisions(monkeypatch):
    tool_response = ProviderResponse(
        "",
        "tool_calls",
        tool_calls=(ToolCall(name="nmap", arguments={"target": "example.test"}),),
    )
    graph_provider = FakeProvider(
        [tool_response, ProviderResponse(valid_result(), "stop")]
    )
    procedural_provider = FakeProvider(
        [tool_response, ProviderResponse(valid_result(), "stop")]
    )
    graph_state = create_analysis_state("example.test", "initial evidence")
    procedural_state = create_analysis_state("example.test", "initial evidence")
    monkeypatch.setattr(
        "pentron.ai.analysis.workflow.run_tool_calls",
        lambda calls, *args: (
            "port 443 open",
            [
                {
                    "command": calls[0].name,
                    "arguments": calls[0].arguments,
                    "result": "port 443 open",
                    "status": "accepted",
                    "blocked": False,
                }
            ],
        ),
    )

    graph_result, graph_records = run_analysis_workflow(
        graph_state.target,
        graph_state.raw_scan,
        graph_provider,
        state=graph_state,
    )
    procedural_result, procedural_records = run_procedural_analysis_workflow(
        procedural_state.target,
        procedural_state.raw_scan,
        procedural_provider,
        state=procedural_state,
    )

    assert graph_result == procedural_result
    assert graph_records == procedural_records
    assert graph_state.raw_scan == procedural_state.raw_scan
