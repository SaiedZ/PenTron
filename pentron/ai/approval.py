"""Human approval policy and application service for AI-proposed actions."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict

from .tool_registry import get as get_ai_tool

ActionRisk = Literal["low", "high", "unknown"]
ActionStatus = Literal[
    "proposed",
    "approved",
    "rejected",
    "expired",
    "executing",
    "executed",
    "failed",
]
Decision = Literal["approved", "rejected"]


class ApprovalError(ValueError):
    """Raised when an approval transition violates lifecycle rules."""


class ProposedAction(BaseModel):
    """Persistable authorization record for one normalized tool proposal."""

    model_config = ConfigDict(extra="forbid")

    id: str
    session_id: int
    name: str
    arguments: dict[str, Any]
    target: str = ""
    rationale: str = "AI-requested investigation"
    risk: ActionRisk
    requires_approval: bool
    status: ActionStatus = "proposed"
    actor: str = "ai"
    reason: str = ""
    proposed_at: datetime
    expires_at: datetime
    decided_at: datetime | None = None
    executed_at: datetime | None = None


DecisionProvider = Callable[[ProposedAction], tuple[Decision, str, str]]


class ApprovalRepository(Protocol):
    def create(self, action: ProposedAction) -> ProposedAction: ...

    def get(self, action_id: str) -> ProposedAction | None: ...

    def decide(
        self, action_id: str, decision: Decision, actor: str, reason: str
    ) -> ProposedAction: ...

    def expire(self, action_id: str) -> ProposedAction: ...

    def claim_execution(self, action_id: str) -> bool: ...

    def finish_execution(
        self, action_id: str, *, succeeded: bool, reason: str = ""
    ) -> ProposedAction: ...

    def list_for_session(self, session_id: int) -> list[ProposedAction]: ...


def classify_action(name: str) -> tuple[ActionRisk, bool]:
    """Return a conservative, auditable policy decision for a tool name."""
    spec = get_ai_tool(name)
    if spec is None:
        return "unknown", True
    if not spec.scope_bound:
        return "low", False
    return "high", True


@dataclass
class ApprovalService:
    """Shared lifecycle service used by web and CLI interaction adapters."""

    repository: ApprovalRepository
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    ttl: timedelta = timedelta(minutes=10)

    def propose(
        self,
        *,
        action_id: str,
        session_id: int,
        name: str,
        arguments: dict[str, Any],
        rationale: str = "AI-requested investigation",
    ) -> ProposedAction:
        record_id = (
            f"approval-{sha256(f'{session_id}:{action_id}'.encode()).hexdigest()[:20]}"
        )
        existing = self.repository.get(record_id)
        if existing is not None:
            return self._expire_if_needed(existing)
        risk, required = classify_action(name)
        now = self.clock()
        target = str(arguments.get("target", arguments.get("query", "")))
        return self.repository.create(
            ProposedAction(
                id=record_id,
                session_id=session_id,
                name=name,
                arguments=arguments,
                target=target,
                risk=risk,
                requires_approval=required,
                status="proposed" if required else "approved",
                actor="ai" if required else "policy",
                reason="" if required else "low-risk action allowed by policy",
                proposed_at=now,
                expires_at=now + self.ttl,
                decided_at=None if required else now,
            )
        )

    def decide(
        self, action_id: str, decision: Decision, *, actor: str, reason: str = ""
    ) -> ProposedAction:
        action = self.get(action_id)
        if action is None:
            raise ApprovalError(f"unknown proposed action: {action_id}")
        if action.status != "proposed":
            transition = f"{action.status} -> {decision}"
            raise ApprovalError(
                f"action {action_id} cannot transition from {transition}"
            )
        return self.repository.decide(action_id, decision, actor, reason)

    def get(self, action_id: str) -> ProposedAction | None:
        action = self.repository.get(action_id)
        return self._expire_if_needed(action) if action is not None else None

    def list_for_session(self, session_id: int) -> list[ProposedAction]:
        return [
            self._expire_if_needed(action)
            for action in self.repository.list_for_session(session_id)
        ]

    def claim_execution(self, action_id: str) -> bool:
        action = self.get(action_id)
        return bool(
            action
            and action.status == "approved"
            and self.repository.claim_execution(action_id)
        )

    def finish_execution(
        self, action_id: str, *, succeeded: bool, reason: str = ""
    ) -> ProposedAction:
        return self.repository.finish_execution(
            action_id, succeeded=succeeded, reason=reason
        )

    def _expire_if_needed(self, action: ProposedAction) -> ProposedAction:
        if action.status == "proposed" and self.clock() >= action.expires_at:
            return self.repository.expire(action.id)
        return action


@dataclass
class PersistentApprovalGate:
    """Bridge workflow execution to the persisted approval lifecycle."""

    service: ApprovalService
    session_id: int
    decision_provider: DecisionProvider
    _records: dict[str, str] = field(default_factory=dict, init=False)

    def authorize(
        self, action_id: str, name: str, arguments: dict[str, Any]
    ) -> tuple[bool, str]:
        action = self.service.propose(
            action_id=action_id,
            session_id=self.session_id,
            name=name,
            arguments=arguments,
        )
        self._records[action_id] = action.id
        if action.status == "proposed":
            decision, actor, reason = self.decision_provider(action)
            current = self.service.get(action.id)
            if current and current.status == "proposed":
                action = self.service.decide(
                    action.id, decision, actor=actor, reason=reason
                )
            else:
                action = current
        if action is None or action.status != "approved":
            reason = action.reason if action else "approval record disappeared"
            return False, reason or "human approval rejected"
        if not self.service.claim_execution(action.id):
            return False, "action was already claimed or executed"
        return True, ""

    def complete(self, action_id: str, *, succeeded: bool, reason: str = "") -> None:
        record_id = self._records.get(action_id)
        if record_id:
            self.service.finish_execution(record_id, succeeded=succeeded, reason=reason)
