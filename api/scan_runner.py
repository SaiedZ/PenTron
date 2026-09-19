#!/usr/bin/env python3
"""
METATRON - api/scan_runner.py
Background function launched via FastAPI's BackgroundTasks for POST
/api/scans. Mirrors metatron.py::new_scan()'s recon -> AI -> save pipeline
exactly, reusing the same db.py/tools.py/llm.py functions, but reports
live progress into the api.jobs store instead of print()ing to a terminal.
"""

from api import jobs
import db
from llm import analyse_target
from providers import get_provider
from tools import run_selected_tools, format_recon_for_llm, resolve_tool_plan


def _make_on_progress(sl_no: int):
    def on_progress(event: str, payload) -> None:
        if event == "tool_start":
            jobs.update_job(sl_no, state="RECON_RUNNING",
                             current_tool=payload, detail=f"running {payload}")
        elif event == "tool_done":
            job = jobs.get_job(sl_no)
            existing = job.completed_tools if job else []
            completed = existing if payload in existing else existing + [payload]
            jobs.update_job(sl_no, detail=f"finished {payload}", completed_tools=completed)
        elif event == "ai_round_start":
            round_num, max_rounds = payload.split("/")
            jobs.update_job(
                sl_no,
                state="AI_ANALYSIS_ROUND",
                current_tool=None,
                round_num=int(round_num),
                max_rounds=int(max_rounds),
                detail=f"AI analysis round {payload}",
            )
        elif event == "tool_dispatch":
            job = jobs.get_job(sl_no)
            existing = job.dispatched_calls if job else []
            calls = [f"{call_type}: {content}" for call_type, content in payload]
            jobs.update_job(sl_no, dispatched_calls=existing + calls)
        elif event == "call_blocked":
            job = jobs.get_job(sl_no)
            existing = job.blocked_calls if job else []
            jobs.update_job(sl_no, blocked_calls=existing + [payload])

    return on_progress


def run_scan_job(sl_no: int, target: str, tool_keys) -> None:
    on_progress = _make_on_progress(sl_no)
    try:
        jobs.update_job(
            sl_no, state="RECON_RUNNING", detail="starting recon",
            planned_tools=resolve_tool_plan(tool_keys), completed_tools=[],
        )
        settings = db.get_settings()
        delay = settings.get("scan_delay_seconds", 0)
        user_agent = settings.get("user_agent") or None
        results = run_selected_tools(target, tool_keys, on_progress=on_progress, delay=delay, user_agent=user_agent)
        raw_scan = format_recon_for_llm(results)

        if not raw_scan.strip():
            jobs.update_job(sl_no, state="FAILED", error="No scan data collected.")
            db.delete_full_session(sl_no)
            return

        provider = get_provider()
        result = analyse_target(target, raw_scan, provider=provider, on_progress=on_progress)

        jobs.update_job(sl_no, state="SAVING_RESULTS", detail="saving results")

        for vuln in result["vulnerabilities"]:
            vuln_id = db.save_vulnerability(
                sl_no,
                vuln["vuln_name"],
                vuln["severity"],
                vuln["port"],
                vuln["service"],
                vuln["description"],
            )
            if vuln.get("fix"):
                db.save_fix(sl_no, vuln_id, vuln["fix"], source="ai")

        for exp in result["exploits"]:
            db.save_exploit(
                sl_no,
                exp["exploit_name"],
                exp["tool_used"],
                exp["payload"],
                exp["result"],
                exp["notes"],
            )

        db.save_summary(sl_no, result["raw_scan"], result["full_response"], result["risk_level"])

        jobs.update_job(sl_no, state="DONE", detail="complete", risk_level=result["risk_level"])

    except Exception as e:
        jobs.update_job(sl_no, state="FAILED", error=str(e))
