from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader

from api.serializers import scan_status_to_view

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = Environment(
    loader=FileSystemLoader(ROOT / "web" / "templates"), autoescape=True
)


def _status(**overrides):
    status = {
        "state": "RECON_RUNNING",
        "detail": "",
        "current_tool": None,
        "planned_tools": [],
        "completed_tools": [],
        "round_num": None,
        "max_rounds": None,
        "approvals": [],
        "risk_level": None,
        "error": None,
        "blocked_calls": [],
        "dispatched_calls": [],
    }
    status.update(overrides)
    return scan_status_to_view(status)


def _render(status):
    template = TEMPLATES.get_template("_scan_status_fragment.html")
    return template.render(sl_no=12, status=status)


@pytest.mark.parametrize(
    ("state", "label"),
    [
        ("RECON_RUNNING", "Reconnaissance in progress"),
        ("AI_ANALYSIS_ROUND", "AI analysis in progress"),
        ("WAITING_APPROVAL", "Waiting for your approval"),
        ("SAVING_RESULTS", "Saving results"),
        ("DONE", "Completed"),
        ("PARTIAL", "Completed with partial results"),
        ("FAILED", "Failed"),
    ],
)
def test_scan_states_have_user_facing_labels(state, label):
    assert scan_status_to_view({"state": state})["display_state"] == label


def test_recon_status_uses_readable_label_without_duplicate_detail():
    html = _render(_status(current_tool="nmap", detail="running nmap"))

    assert "Status: Reconnaissance in progress" in html
    assert html.count("nmap") == 1
    assert "Currently running: nmap" in html
    assert "RECON_RUNNING" not in html


def test_waiting_approval_renders_decision_controls_and_readable_round():
    approval = {
        "id": "approval-123",
        "name": "nmap",
        "target": "example.test",
        "rationale": "Collect additional evidence",
        "risk": "high",
        "status": "proposed",
        "reason": "",
    }
    html = _render(
        _status(
            state="WAITING_APPROVAL",
            detail="review the proposed investigation",
            round_num=1,
            max_rounds=9,
            approvals=[approval],
        )
    )

    assert "Status: Waiting for your approval" in html
    assert "Round 1 of 9" in html
    assert "Human approval" in html
    assert ">Approve</button>" in html
    assert ">Reject</button>" in html
    assert "/api/scans/12/approvals/approval-123/approved" in html
    assert "WAITING_APPROVAL" not in html
