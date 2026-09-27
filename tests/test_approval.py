from datetime import UTC, datetime, timedelta

import pytest

from pentron.ai.approval import (
    ApprovalError,
    ApprovalService,
    PersistentApprovalGate,
    ProposedAction,
    classify_action,
)


class MemoryApprovalRepository:
    def __init__(self):
        self.actions = {}

    def create(self, action):
        if action.id in self.actions:
            raise ApprovalError("duplicate action")
        self.actions[action.id] = action
        return action

    def get(self, action_id):
        return self.actions.get(action_id)

    def decide(self, action_id, decision, actor, reason):
        action = self.actions[action_id]
        if action.status != "proposed":
            raise ApprovalError("already decided")
        action = action.model_copy(
            update={
                "status": decision,
                "actor": actor,
                "reason": reason,
                "decided_at": datetime.now(UTC),
            }
        )
        self.actions[action_id] = action
        return action

    def expire(self, action_id):
        action = self.actions[action_id].model_copy(
            update={
                "status": "expired",
                "actor": "system",
                "reason": "approval request expired",
            }
        )
        self.actions[action_id] = action
        return action

    def claim_execution(self, action_id):
        action = self.actions[action_id]
        if action.status != "approved":
            return False
        self.actions[action_id] = action.model_copy(update={"status": "executing"})
        return True

    def finish_execution(self, action_id, *, succeeded, reason=""):
        action = self.actions[action_id]
        if action.status != "executing":
            raise ApprovalError("not executing")
        action = action.model_copy(
            update={"status": "executed" if succeeded else "failed", "reason": reason}
        )
        self.actions[action_id] = action
        return action

    def list_for_session(self, session_id):
        return [a for a in self.actions.values() if a.session_id == session_id]


def service(clock=lambda: datetime(2026, 1, 1, tzinfo=UTC)):
    return ApprovalService(MemoryApprovalRepository(), clock=clock)


def test_policy_requires_approval_for_active_and_unknown_tools():
    assert classify_action("web_search") == ("low", False)
    assert classify_action("nmap") == ("high", True)
    assert classify_action("unregistered") == ("unknown", True)


def test_lifecycle_rejects_duplicate_decisions_and_executes_once():
    approvals = service()
    action = approvals.propose(
        action_id="proposal-1",
        session_id=7,
        name="nmap",
        arguments={"target": "example.com"},
    )
    approved = approvals.decide(action.id, "approved", actor="alice")
    assert approved.status == "approved"
    with pytest.raises(ApprovalError, match="cannot transition"):
        approvals.decide(action.id, "approved", actor="bob")
    assert approvals.claim_execution(action.id) is True
    assert approvals.claim_execution(action.id) is False
    assert approvals.finish_execution(action.id, succeeded=True).status == "executed"


def test_expired_and_rejected_actions_cannot_execute():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    approvals = service(clock=lambda: now + timedelta(minutes=11))
    expired = ProposedAction(
        id="expired",
        session_id=1,
        name="nmap",
        arguments={"target": "example.com"},
        risk="high",
        requires_approval=True,
        proposed_at=now,
        expires_at=now + timedelta(minutes=10),
    )
    approvals.repository.create(expired)
    assert approvals.get(expired.id).status == "expired"
    assert approvals.claim_execution(expired.id) is False


def test_gate_uses_same_service_for_rejection_and_execution_completion():
    approvals = service()
    rejected_gate = PersistentApprovalGate(
        approvals, 1, lambda action: ("rejected", "tester", "not authorized")
    )
    allowed, reason = rejected_gate.authorize(
        "first", "nmap", {"target": "example.com"}
    )
    assert allowed is False
    assert reason == "not authorized"

    approved_gate = PersistentApprovalGate(
        approvals, 1, lambda action: ("approved", "tester", "in scope")
    )
    allowed, reason = approved_gate.authorize(
        "second", "nmap", {"target": "example.com"}
    )
    assert allowed is True
    assert reason == ""
    approved_gate.complete("second", succeeded=True)
    actions = approvals.list_for_session(1)
    assert {action.status for action in actions} == {"rejected", "executed"}


def test_low_risk_action_is_policy_approved_without_prompt():
    approvals = service()

    def should_not_run(action):
        raise AssertionError("low-risk action should not prompt")

    gate = PersistentApprovalGate(approvals, 2, should_not_run)
    allowed, _ = gate.authorize("search", "web_search", {"query": "CVE"})
    assert allowed is True


def test_resume_uses_persisted_decision_without_asking_again():
    approvals = service()
    action = approvals.propose(
        action_id="resume",
        session_id=3,
        name="nmap",
        arguments={"target": "example.com"},
    )
    approvals.decide(action.id, "approved", actor="web")

    def should_not_run(action):
        raise AssertionError("a persisted decision must win during resume")

    resumed_gate = PersistentApprovalGate(approvals, 3, should_not_run)
    allowed, _ = resumed_gate.authorize("resume", "nmap", {"target": "example.com"})
    assert allowed is True
