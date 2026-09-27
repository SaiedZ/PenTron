"""Typed, serializable state for the procedural analysis workflow."""

import json
from hashlib import sha256
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..evidence import Fact, Finding, Hypothesis, Observation
from ..models import AnalysisResult
from ..tool_calls import RejectedToolCall, ToolCall

AnalysisStatus = Literal["ready", "running", "awaiting_actions", "completed", "failed"]
ExecutionStatus = Literal["accepted", "blocked", "rejected"]


class AnalysisStateError(ValueError):
    """Raised when a state transition would violate workflow invariants."""


class DuplicateActionError(AnalysisStateError):
    """Raised when a proposal has already been queued or executed."""


def _action_id(name: str, arguments: Any) -> str:
    payload = json.dumps(
        {"name": name, "arguments": arguments},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return f"action-{sha256(payload.encode()).hexdigest()[:16]}"


class PendingAction(BaseModel):
    """A normalized provider proposal waiting for a recorded execution."""

    model_config = ConfigDict(extra="forbid")

    id: str
    iteration: int = Field(ge=1)
    name: str
    arguments: Any
    source: Literal["native", "fallback"] = "native"

    @classmethod
    def from_tool_call(cls, call: ToolCall, iteration: int) -> "PendingAction":
        return cls(
            id=_action_id(call.name, call.arguments),
            iteration=iteration,
            name=call.name,
            arguments=call.arguments,
            source=call.source,
        )

    @classmethod
    def from_rejected(cls, call: RejectedToolCall, iteration: int) -> "PendingAction":
        return cls(
            id=_action_id(call.name, call.arguments),
            iteration=iteration,
            name=call.name,
            arguments=call.arguments,
        )


class ToolExecution(BaseModel):
    """Auditable outcome linked to the exact proposal that caused it."""

    model_config = ConfigDict(extra="forbid")

    proposal_id: str
    proposal: PendingAction
    iteration: int = Field(ge=1)
    call_type: str = "TOOL"
    status: ExecutionStatus
    result: str = ""
    reason: str = ""

    @model_validator(mode="after")
    def proposal_matches(self):
        if self.proposal_id != self.proposal.id:
            raise ValueError("execution proposal_id does not match its proposal")
        if self.iteration != self.proposal.iteration:
            raise ValueError("execution iteration does not match its proposal")
        return self

    def as_audit_record(self) -> dict:
        return {
            "call_type": self.call_type,
            "command": self.proposal.name,
            "arguments": self.proposal.arguments,
            "result": self.result,
            "status": self.status,
            "reason": self.reason,
            "blocked": self.status != "accepted",
        }


_ALLOWED_TRANSITIONS = {
    "ready": {"running", "failed"},
    "running": {"awaiting_actions", "completed", "failed"},
    "awaiting_actions": {"running", "failed"},
    "completed": set(),
    "failed": {"running"},
}


class AnalysisState(BaseModel):
    """Single source of truth carried across analysis iterations and resumes.

    Lifecycle: ``ready -> running -> awaiting_actions -> running`` may repeat,
    then ``running -> completed``. Failures are inspectable and may explicitly
    resume through ``failed -> running``.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    schema_version: int = 1
    target: str = Field(min_length=1)
    raw_scan: str
    iteration: int = Field(default=0, ge=0)
    status: AnalysisStatus = "ready"
    observations: list[Observation] = Field(default_factory=list)
    facts: list[Fact] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    pending_actions: list[PendingAction] = Field(default_factory=list)
    executions: list[ToolExecution] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    final_result: AnalysisResult | None = None

    @model_validator(mode="after")
    def valid_state(self):
        observation_ids = {item.id for item in self.observations}
        fact_ids = {item.id for item in self.facts}
        hypothesis_ids = {item.id for item in self.hypotheses}
        if len(observation_ids) != len(self.observations):
            raise ValueError("observation IDs must be unique")
        if len(fact_ids) != len(self.facts):
            raise ValueError("fact IDs must be unique")
        if len(hypothesis_ids) != len(self.hypotheses):
            raise ValueError("hypothesis IDs must be unique")
        for fact in self.facts:
            if missing := set(fact.observation_ids) - observation_ids:
                raise ValueError(f"fact {fact.id} has broken observations: {missing}")
        for hypothesis in self.hypotheses:
            if missing := set(hypothesis.evidence_observation_ids) - observation_ids:
                raise ValueError(
                    f"hypothesis {hypothesis.id} has broken observations: {missing}"
                )
        for finding in self.findings:
            if missing := set(finding.fact_ids) - fact_ids:
                raise ValueError(f"finding {finding.id} has broken facts: {missing}")
            if missing := set(finding.hypothesis_ids) - hypothesis_ids:
                raise ValueError(
                    f"finding {finding.id} has broken hypotheses: {missing}"
                )
        pending_ids = [item.id for item in self.pending_actions]
        execution_ids = [item.proposal_id for item in self.executions]
        if len(set(pending_ids)) != len(pending_ids):
            raise ValueError("pending action IDs must be unique")
        if len(set(execution_ids)) != len(execution_ids):
            raise ValueError("a proposal can only have one execution")
        if set(pending_ids) & set(execution_ids):
            raise ValueError("an executed action cannot remain pending")
        if self.status == "ready" and self.iteration != 0:
            raise ValueError("ready state cannot have started iterations")
        if self.status == "completed" and self.final_result is None:
            raise ValueError("completed state requires a final result")
        if self.final_result is not None and self.status != "completed":
            raise ValueError("final result is only valid in completed state")
        return self

    def transition_to(self, status: AnalysisStatus) -> None:
        if status not in _ALLOWED_TRANSITIONS[self.status]:
            raise AnalysisStateError(f"invalid transition: {self.status} -> {status}")
        self.status = status

    def start_iteration(self) -> int:
        if self.status not in {"ready", "awaiting_actions", "failed"}:
            raise AnalysisStateError(f"cannot start iteration from {self.status}")
        self.transition_to("running")
        self.iteration += 1
        return self.iteration

    def queue(self, action: PendingAction) -> None:
        if self.status != "running":
            raise AnalysisStateError("actions can only be queued while running")
        if action.iteration != self.iteration:
            raise AnalysisStateError("action iteration does not match current state")
        if self.execution_for(action.id) or any(
            item.id == action.id for item in self.pending_actions
        ):
            raise DuplicateActionError(f"action {action.id} was already proposed")
        self.pending_actions.append(action)

    def record_execution(
        self,
        action: PendingAction,
        *,
        status: ExecutionStatus,
        result: str = "",
        reason: str = "",
        call_type: str = "TOOL",
    ) -> ToolExecution:
        if self.execution_for(action.id):
            raise DuplicateActionError(f"action {action.id} was already executed")
        if not any(item.id == action.id for item in self.pending_actions):
            raise AnalysisStateError(f"action {action.id} is not pending")
        execution = ToolExecution(
            proposal_id=action.id,
            proposal=action,
            iteration=self.iteration,
            call_type=call_type,
            status=status,
            result=result,
            reason=reason,
        )
        self.pending_actions = [
            item for item in self.pending_actions if item.id != action.id
        ]
        self.executions.append(execution)
        return execution

    def execution_for(self, proposal_id: str) -> ToolExecution | None:
        return next(
            (item for item in self.executions if item.proposal_id == proposal_id),
            None,
        )

    def audit_records(self) -> list[dict]:
        return [execution.as_audit_record() for execution in self.executions]

    def complete(self, result: AnalysisResult) -> None:
        if self.status != "running":
            raise AnalysisStateError(f"cannot complete analysis from {self.status}")
        completed = self.model_validate(
            {
                **self.model_dump(mode="python"),
                "status": "completed",
                "final_result": result,
            }
        )
        object.__setattr__(self, "status", completed.status)
        object.__setattr__(self, "final_result", completed.final_result)
