#!/usr/bin/env python3
"""
PENTRON - api/serializers.py
Map db.py's raw tuple rows (column order defined in docker/schema.sql) to
named dicts, in one place, so raw index-based tuples never leak into JSON
responses.
"""


def history_to_dict(row) -> dict:
    if row is None:
        return None
    sl_no, target, scan_date, status = row
    return {
        "sl_no": sl_no,
        "target": target,
        "scan_date": str(scan_date) if scan_date else None,
        "status": status,
    }


def vuln_to_dict(row) -> dict:
    id_, sl_no, vuln_name, severity, port, service, description = row
    return {
        "id": id_,
        "sl_no": sl_no,
        "vuln_name": vuln_name,
        "severity": severity,
        "port": port,
        "service": service,
        "description": description,
    }


def fix_to_dict(row) -> dict:
    id_, sl_no, vuln_id, fix_text, source = row
    return {
        "id": id_,
        "sl_no": sl_no,
        "vuln_id": vuln_id,
        "fix_text": fix_text,
        "source": source,
    }


def summary_to_dict(row) -> dict:
    if row is None:
        return None
    (
        id_,
        sl_no,
        raw_scan,
        ai_analysis,
        risk_level,
        generated_at,
        short_summary,
        analysis_status,
        analysis_error,
    ) = row
    return {
        "id": id_,
        "sl_no": sl_no,
        "raw_scan": raw_scan,
        "ai_analysis": ai_analysis,
        "risk_level": risk_level,
        "generated_at": str(generated_at) if generated_at else None,
        "short_summary": short_summary,
        "analysis_status": analysis_status,
        "analysis_error": analysis_error,
    }


def suggestion_to_dict(row) -> dict:
    id_, sl_no, name, rationale, tool, safe_validation = row
    return {
        "id": id_,
        "sl_no": sl_no,
        "name": name,
        "rationale": rationale,
        "tool": tool,
        "safe_validation": safe_validation,
    }


def tool_call_to_dict(row) -> dict:
    id_, sl_no, call_type, command, result, blocked, *audit = row
    return {
        "id": id_,
        "sl_no": sl_no,
        "call_type": call_type,
        "command": command,
        "result": result,
        "blocked": bool(blocked),
        "arguments": audit[0] if len(audit) > 0 else "{}",
        "status": audit[1]
        if len(audit) > 1
        else ("blocked" if blocked else "accepted"),
        "reason": audit[2] if len(audit) > 2 else "",
    }


def session_to_dict(data: dict) -> dict:
    """data is db.get_session()'s return shape: history/vulns/fixes/summary."""
    return {
        "history": history_to_dict(data["history"]),
        "vulnerabilities": [vuln_to_dict(v) for v in data["vulns"]],
        "fixes": [fix_to_dict(f) for f in data["fixes"]],
        "summary": summary_to_dict(data["summary"]),
        "suggestions": [suggestion_to_dict(x) for x in data["suggestions"]],
        "tool_calls": [tool_call_to_dict(x) for x in data["tool_calls"]],
        "evidence_domain": data.get("evidence_domain"),
    }


def mask_api_key(key: str) -> str:
    if not key:
        return None
    if len(key) <= 4:
        return "*" * len(key)
    return f"{'*' * (len(key) - 4)}{key[-4:]}"


SCAN_STATUS_LABELS = {
    "QUEUED": "Queued",
    "RECON_RUNNING": "Reconnaissance in progress",
    "AI_ANALYSIS_ROUND": "AI analysis in progress",
    "WAITING_APPROVAL": "Waiting for your approval",
    "SAVING_RESULTS": "Saving results",
    "DONE": "Completed",
    "PARTIAL": "Completed with partial results",
    "FAILED": "Failed",
    "UNKNOWN": "Status unavailable",
}


def scan_status_to_view(status: dict) -> dict:
    """Add user-facing progress fields without changing the API status contract."""
    view = dict(status)
    state = status.get("state", "UNKNOWN")
    current_tool = status.get("current_tool")
    detail = status.get("detail") or ""

    view["display_state"] = SCAN_STATUS_LABELS.get(
        state, state.replace("_", " ").title()
    )
    view["phase_state"] = "AI_ANALYSIS_ROUND" if state == "WAITING_APPROVAL" else state
    duplicate_tool_detail = (
        current_tool and detail.casefold() == f"running {current_tool}".casefold()
    )
    view["display_detail"] = "" if duplicate_tool_detail else detail
    return view
