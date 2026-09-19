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


def exploit_to_dict(row) -> dict:
    id_, sl_no, exploit_name, tool_used, payload, result, notes = row
    return {
        "id": id_,
        "sl_no": sl_no,
        "exploit_name": exploit_name,
        "tool_used": tool_used,
        "payload": payload,
        "result": result,
        "notes": notes,
    }


def summary_to_dict(row) -> dict:
    if row is None:
        return None
    id_, sl_no, raw_scan, ai_analysis, risk_level, generated_at = row
    return {
        "id": id_,
        "sl_no": sl_no,
        "raw_scan": raw_scan,
        "ai_analysis": ai_analysis,
        "risk_level": risk_level,
        "generated_at": str(generated_at) if generated_at else None,
    }


def session_to_dict(data: dict) -> dict:
    """data is db.get_session()'s return shape: history/vulns/fixes/exploits/summary."""
    return {
        "history": history_to_dict(data["history"]),
        "vulnerabilities": [vuln_to_dict(v) for v in data["vulns"]],
        "fixes": [fix_to_dict(f) for f in data["fixes"]],
        "exploits": [exploit_to_dict(e) for e in data["exploits"]],
        "summary": summary_to_dict(data["summary"]),
    }


def mask_api_key(key: str) -> str:
    if not key:
        return None
    if len(key) <= 4:
        return "*" * len(key)
    return f"{'*' * (len(key) - 4)}{key[-4:]}"
