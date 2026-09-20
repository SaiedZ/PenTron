#!/usr/bin/env python3
"""
PENTRON - api/scan_runner.py
Background function launched via FastAPI's BackgroundTasks for POST
/api/scans. Mirrors pentron.cli::new_scan()'s recon -> AI -> save pipeline
exactly, reusing the same db.py/tools.py/llm.py functions, but reports
live progress into the api.jobs store instead of print()ing to a terminal.
"""

from api import jobs
from pentron import db
from pentron.analysis_pipeline import analyse_and_save
from pentron.providers import get_provider
from pentron.tools import (
    discover_subdomains,
    format_recon_for_llm,
    resolve_tool_plan,
    run_selected_tools,
)


def _make_on_progress(sl_no: int):
    def on_progress(event: str, payload) -> None:
        if event == "tool_start":
            jobs.update_job(
                sl_no,
                state="RECON_RUNNING",
                current_tool=payload,
                detail=f"running {payload}",
            )
        elif event == "tool_done":
            job = jobs.get_job(sl_no)
            existing = job.completed_tools if job else []
            completed = existing if payload in existing else existing + [payload]
            jobs.update_job(
                sl_no, detail=f"finished {payload}", completed_tools=completed
            )
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
        elif event == "saving_results":
            jobs.update_job(
                sl_no,
                state="SAVING_RESULTS",
                detail="saving results",
                current_tool=None,
            )

    return on_progress


def run_scan_job(
    sl_no: int, target: str, tool_keys, subdomain_level: int = None
) -> None:
    on_progress = _make_on_progress(sl_no)
    try:
        settings = db.get_settings()
        if subdomain_level is None:
            subdomain_level = settings.get("subdomain_discovery_level", 0)
        planned_tools = resolve_tool_plan(tool_keys)
        if subdomain_level > 0:
            planned_tools = ["Subdomain discovery"] + planned_tools
        jobs.update_job(
            sl_no,
            state="RECON_RUNNING",
            detail="starting recon",
            planned_tools=planned_tools,
            completed_tools=[],
        )
        delay = settings.get("scan_delay_seconds", 0)
        user_agent = settings.get("user_agent") or None

        subdomain_text, allowed_subdomains = "", frozenset()
        if subdomain_level > 0:
            on_progress("tool_start", "Subdomain discovery")
            subdomain_text, allowed_subdomains = discover_subdomains(
                target, subdomain_level
            )
            on_progress("tool_done", "Subdomain discovery")

        results = run_selected_tools(
            target,
            tool_keys,
            on_progress=on_progress,
            delay=delay,
            user_agent=user_agent,
        )
        raw_scan = subdomain_text + format_recon_for_llm(results)

        if not raw_scan.strip():
            jobs.update_job(sl_no, state="FAILED", error="No scan data collected.")
            db.update_session_status(sl_no, "failed")
            return

        provider = get_provider()
        status, result, error = analyse_and_save(
            sl_no,
            target,
            raw_scan,
            provider=provider,
            on_progress=on_progress,
            allowed_subdomains=allowed_subdomains,
        )

        if status == "partial":
            jobs.update_job(
                sl_no,
                state="PARTIAL",
                detail="AI analysis incomplete",
                error=error,
                current_tool=None,
                round_num=None,
                max_rounds=None,
            )
        else:
            assert result is not None
            jobs.update_job(
                sl_no,
                state="DONE",
                detail="complete",
                risk_level=result["risk_level"],
                current_tool=None,
                round_num=None,
                max_rounds=None,
            )

    except Exception as e:
        try:
            db.update_session_status(sl_no, "failed")
        except Exception:
            pass
        jobs.update_job(sl_no, state="FAILED", error=str(e))
