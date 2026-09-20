#!/usr/bin/env python3
"""
PENTRON - api/jobs.py
In-memory scan progress tracking. Single uvicorn worker only (see
docker-compose.yml comment on the `web` service) — job state is a plain
process-local dict, not durable storage. The DB rows written by db.py are
the durable record; this is just a live progress indicator for the UI.
"""

import threading
from dataclasses import dataclass, field
from datetime import datetime

VALID_STATES = (
    "QUEUED",
    "RECON_RUNNING",
    "AI_ANALYSIS_ROUND",
    "SAVING_RESULTS",
    "DONE",
    "PARTIAL",
    "FAILED",
)


@dataclass
class JobStatus:
    sl_no: int
    state: str = "QUEUED"
    detail: str = ""
    current_tool: str = None
    planned_tools: list = field(default_factory=list)
    completed_tools: list = field(default_factory=list)
    round_num: int = None
    max_rounds: int = None
    dispatched_calls: list = field(default_factory=list)
    blocked_calls: list = field(default_factory=list)
    risk_level: str = None
    error: str = None
    updated_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "sl_no": self.sl_no,
            "state": self.state,
            "detail": self.detail,
            "current_tool": self.current_tool,
            "planned_tools": self.planned_tools,
            "completed_tools": self.completed_tools,
            "round_num": self.round_num,
            "max_rounds": self.max_rounds,
            "dispatched_calls": self.dispatched_calls,
            "blocked_calls": self.blocked_calls,
            "risk_level": self.risk_level,
            "error": self.error,
            "updated_at": self.updated_at.isoformat(),
        }


_JOBS = {}
_LOCK = threading.Lock()


def create_job(sl_no: int) -> JobStatus:
    with _LOCK:
        job = JobStatus(sl_no=sl_no)
        _JOBS[sl_no] = job
        return job


def update_job(sl_no: int, **kwargs) -> None:
    with _LOCK:
        job = _JOBS.get(sl_no)
        if job is None:
            job = JobStatus(sl_no=sl_no)
            _JOBS[sl_no] = job
        for key, value in kwargs.items():
            if hasattr(job, key):
                setattr(job, key, value)
        job.updated_at = datetime.now()


def get_job(sl_no: int) -> JobStatus:
    with _LOCK:
        return _JOBS.get(sl_no)


def resolve_status(sl_no: int):
    """
    Shared by the JSON status endpoint and the HTMX progress fragment.
    Falls back to the DB if the job isn't in memory (process restarted
    mid-scan or after completion) rather than reporting a bare 404 for a
    scan that may well have finished successfully. Returns None if sl_no
    doesn't exist at all.
    """
    job = get_job(sl_no)
    if job is not None:
        return job.to_dict()

    from pentron import db

    data = db.get_session(sl_no)
    if not data["history"]:
        return None
    if data["summary"]:
        persisted = (data["history"][3] or "").upper()
        state = "PARTIAL" if persisted == "PARTIAL" else "DONE"
        return {
            "sl_no": sl_no,
            "state": state,
            "detail": data["summary"][8] or "",
            "current_tool": None,
            "planned_tools": [],
            "completed_tools": [],
            "round_num": None,
            "max_rounds": None,
            "dispatched_calls": [],
            "blocked_calls": [],
            "risk_level": data["summary"][4],
            "error": None,
        }
    return {
        "sl_no": sl_no,
        "state": "UNKNOWN",
        "detail": "process restarted, check history",
        "current_tool": None,
        "planned_tools": [],
        "completed_tools": [],
        "round_num": None,
        "max_rounds": None,
        "dispatched_calls": [],
        "blocked_calls": [],
        "risk_level": None,
        "error": None,
    }
