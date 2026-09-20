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
    id_, sl_no, call_type, command, result, blocked = row
    return {
        "id": id_,
        "sl_no": sl_no,
        "call_type": call_type,
        "command": command,
        "result": result,
        "blocked": bool(blocked),
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
    }


def mask_api_key(key: str) -> str:
    if not key:
        return None
    if len(key) <= 4:
        return "*" * len(key)
    return f"{'*' * (len(key) - 4)}{key[-4:]}"
