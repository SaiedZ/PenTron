#!/usr/bin/env python3
"""
PENTRON - db.py
MariaDB connection + all read/write/edit/delete operations
Database: pentron
"""

import os
from datetime import datetime

import mysql.connector

# ─────────────────────────────────────────────
# CONNECTION
# ─────────────────────────────────────────────


def get_connection():
    """Returns a MariaDB connection. Values overridable via env vars for Docker."""
    return mysql.connector.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        user=os.environ.get("DB_USER", "pentron"),
        password=os.environ.get("DB_PASSWORD", "123"),
        database=os.environ.get("DB_NAME", "pentron"),
    )


# ─────────────────────────────────────────────
# WRITE FUNCTIONS
# ─────────────────────────────────────────────


def create_session(target: str) -> int:
    """Insert new row into history. Returns sl_no."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT INTO history (target, scan_date, status) VALUES (%s, %s, %s)",
        (target, now, "active"),
    )
    conn.commit()
    sl_no = c.lastrowid
    conn.close()
    return sl_no


def _ensure_analysis_schema(cursor) -> None:
    """Idempotent upgrade path for analysis data added after initial release."""
    cursor.execute(
        "ALTER TABLE summary ADD COLUMN IF NOT EXISTS short_summary TEXT NULL"
    )
    cursor.execute(
        "ALTER TABLE summary ADD COLUMN IF NOT EXISTS "
        "analysis_status VARCHAR(50) DEFAULT 'complete'"
    )
    cursor.execute(
        "ALTER TABLE summary ADD COLUMN IF NOT EXISTS analysis_error TEXT NULL"
    )
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS exploit_suggestions (
          id INT AUTO_INCREMENT PRIMARY KEY,
          sl_no INT, name TEXT, rationale TEXT, tool TEXT, safe_validation TEXT,
          FOREIGN KEY (sl_no) REFERENCES history(sl_no)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ai_tool_calls (
          id INT AUTO_INCREMENT PRIMARY KEY,
          sl_no INT, call_type VARCHAR(20), command TEXT, result LONGTEXT,
          blocked BOOLEAN DEFAULT FALSE,
          FOREIGN KEY (sl_no) REFERENCES history(sl_no)
        )
    """)


def update_session_status(sl_no: int, status: str) -> None:
    if status not in {"active", "done", "partial", "failed"}:
        raise ValueError(f"Invalid session status: {status}")
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE history SET status = %s WHERE sl_no = %s", (status, sl_no))
    conn.commit()
    conn.close()


def save_analysis_result(sl_no: int, result: dict) -> None:
    """Persist one validated analysis and mark the session done atomically."""
    conn = get_connection()
    c = conn.cursor()
    try:
        _ensure_analysis_schema(c)
        for vuln in result["vulnerabilities"]:
            c.execute(
                """INSERT INTO vulnerabilities
                   (sl_no, vuln_name, severity, port, service, description)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (
                    sl_no,
                    vuln["vuln_name"],
                    vuln["severity"],
                    vuln["port"],
                    vuln["service"],
                    vuln["description"],
                ),
            )
            if vuln.get("fix"):
                c.execute(
                    "INSERT INTO fixes (sl_no, vuln_id, fix_text, source) "
                    "VALUES (%s, %s, %s, 'ai')",
                    (sl_no, c.lastrowid, vuln["fix"]),
                )
        for suggestion in result["exploit_suggestions"]:
            c.execute(
                """INSERT INTO exploit_suggestions
                   (sl_no, name, rationale, tool, safe_validation)
                   VALUES (%s, %s, %s, %s, %s)""",
                (
                    sl_no,
                    suggestion["name"],
                    suggestion["rationale"],
                    suggestion.get("tool", ""),
                    suggestion.get("safe_validation", ""),
                ),
            )
        _save_tool_calls(c, sl_no, result.get("tool_calls", []))
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute(
            """INSERT INTO summary
               (sl_no, raw_scan, ai_analysis, risk_level, generated_at,
                short_summary, analysis_status, analysis_error)
               VALUES (%s, %s, %s, %s, %s, %s, 'complete', NULL)""",
            (
                sl_no,
                result["raw_scan"],
                result["full_response"],
                result["risk_level"],
                now,
                result["summary"],
            ),
        )
        c.execute("UPDATE history SET status = 'done' WHERE sl_no = %s", (sl_no,))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _save_tool_calls(cursor, sl_no: int, calls: list) -> None:
    for call in calls:
        cursor.execute(
            """INSERT INTO ai_tool_calls
               (sl_no, call_type, command, result, blocked)
               VALUES (%s, %s, %s, %s, %s)""",
            (
                sl_no,
                call["call_type"],
                call["command"],
                call["result"],
                bool(call["blocked"]),
            ),
        )


def save_partial_analysis(
    sl_no: int, raw_scan: str, raw_response: str, error: str, tool_calls: list
) -> None:
    """Keep recon and diagnostics when the AI contract cannot be validated."""
    conn = get_connection()
    c = conn.cursor()
    try:
        _ensure_analysis_schema(c)
        _save_tool_calls(c, sl_no, tool_calls)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute(
            """INSERT INTO summary
               (sl_no, raw_scan, ai_analysis, risk_level, generated_at,
                short_summary, analysis_status, analysis_error)
               VALUES (%s, %s, %s, 'UNKNOWN', %s, '', 'partial', %s)""",
            (sl_no, raw_scan, raw_response, now, error),
        )
        c.execute("UPDATE history SET status = 'partial' WHERE sl_no = %s", (sl_no,))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def save_vulnerability(
    sl_no: int, vuln_name: str, severity: str, port: str, service: str, description: str
) -> int:
    """Insert a vulnerability. Returns its id."""
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO vulnerabilities
            (sl_no, vuln_name, severity, port, service, description)
        VALUES (%s, %s, %s, %s, %s, %s)
    """,
        (sl_no, vuln_name, severity, port, service, description),
    )
    conn.commit()
    vuln_id = c.lastrowid
    conn.close()
    return vuln_id


def save_fix(sl_no: int, vuln_id: int, fix_text: str, source: str = "ai"):
    """Insert a fix linked to a vulnerability."""
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO fixes (sl_no, vuln_id, fix_text, source)
        VALUES (%s, %s, %s, %s)
    """,
        (sl_no, vuln_id, fix_text, source),
    )
    conn.commit()
    conn.close()


def save_summary(sl_no: int, raw_scan: str, ai_analysis: str, risk_level: str):
    """Insert the full session summary."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        """
        INSERT INTO summary (sl_no, raw_scan, ai_analysis, risk_level, generated_at)
        VALUES (%s, %s, %s, %s, %s)
    """,
        (sl_no, raw_scan, ai_analysis, risk_level, now),
    )
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# READ FUNCTIONS
# ─────────────────────────────────────────────


def get_all_history():
    """Return all rows from history ordered by newest first."""
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT sl_no, target, scan_date, status FROM history ORDER BY sl_no DESC"
    )
    rows = c.fetchall()
    conn.close()
    return rows


def get_session(sl_no: int) -> dict:
    """Return everything linked to a sl_no across all tables."""
    conn = get_connection()
    c = conn.cursor()

    _ensure_analysis_schema(c)
    c.execute("SELECT * FROM history WHERE sl_no = %s", (sl_no,))
    history = c.fetchone()

    c.execute("SELECT * FROM vulnerabilities WHERE sl_no = %s", (sl_no,))
    vulns = c.fetchall()

    c.execute("SELECT * FROM fixes WHERE sl_no = %s", (sl_no,))
    fixes = c.fetchall()

    c.execute(
        """SELECT id, sl_no, raw_scan, ai_analysis, risk_level, generated_at,
                  short_summary, analysis_status, analysis_error
           FROM summary WHERE sl_no = %s""",
        (sl_no,),
    )
    summary = c.fetchone()

    c.execute("SELECT * FROM exploit_suggestions WHERE sl_no = %s", (sl_no,))
    suggestions = c.fetchall()
    c.execute("SELECT * FROM ai_tool_calls WHERE sl_no = %s", (sl_no,))
    tool_calls = c.fetchall()

    conn.close()

    return {
        "history": history,
        "vulns": vulns,
        "fixes": fixes,
        "summary": summary,
        "suggestions": suggestions,
        "tool_calls": tool_calls,
    }


def get_vulnerabilities(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM vulnerabilities WHERE sl_no = %s", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_fixes(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM fixes WHERE sl_no = %s", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


# ─────────────────────────────────────────────
# EDIT FUNCTIONS
# ─────────────────────────────────────────────


def edit_vulnerability(vuln_id: int, field: str, value: str):
    """Edit a single field in vulnerabilities by id."""
    allowed = {"vuln_name", "severity", "port", "service", "description"}
    if field not in allowed:
        print(f"[!] Invalid field: {field}. Allowed: {allowed}")
        return
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"UPDATE vulnerabilities SET {field} = %s WHERE id = %s", (value, vuln_id)
    )
    conn.commit()
    conn.close()
    print(f"[+] vulnerabilities.{field} updated for id={vuln_id}")


def edit_fix(fix_id: int, fix_text: str):
    """Edit the fix_text of a fix by id."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE fixes SET fix_text = %s WHERE id = %s", (fix_text, fix_id))
    conn.commit()
    conn.close()
    print(f"[+] fix id={fix_id} updated.")


def edit_summary_risk(sl_no: int, risk_level: str):
    """Update the risk level on a summary."""
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "UPDATE summary SET risk_level = %s WHERE sl_no = %s", (risk_level, sl_no)
    )
    conn.commit()
    conn.close()
    print(f"[+] Summary risk_level updated for SL#{sl_no}")


# ─────────────────────────────────────────────
# DELETE FUNCTIONS
# ─────────────────────────────────────────────


def delete_vulnerability(vuln_id: int):
    """Delete a single vulnerability and its linked fixes."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes WHERE vuln_id = %s", (vuln_id,))
    c.execute("DELETE FROM vulnerabilities WHERE id = %s", (vuln_id,))
    conn.commit()
    conn.close()
    print(f"[+] Vulnerability id={vuln_id} and its fixes deleted.")


def delete_fix(fix_id: int):
    """Delete a single fix."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes WHERE id = %s", (fix_id,))
    conn.commit()
    conn.close()
    print(f"[+] Fix id={fix_id} deleted.")


def delete_full_session(sl_no: int):
    """
    Wipe everything linked to a sl_no across all tables.
    Order matters — delete children before parent (FK constraints).
    """
    conn = get_connection()
    c = conn.cursor()
    _ensure_analysis_schema(c)
    c.execute("DELETE FROM fixes             WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM ai_tool_calls      WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM exploit_suggestions WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM vulnerabilities   WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM summary           WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM history           WHERE sl_no = %s", (sl_no,))
    conn.commit()
    conn.close()
    print(f"[+] Full session SL#{sl_no} deleted from all tables.")


# ─────────────────────────────────────────────
# SETTINGS (single-row runtime config)
# ─────────────────────────────────────────────

_SETTINGS_DEFAULTS = {
    "provider": os.environ.get("LLM_PROVIDER", "ollama"),
    "model": os.environ.get("PENTRON_MODEL", "huihui_ai/qwen3.5-abliterated:9b"),
    "ollama_host": os.environ.get("OLLAMA_HOST", "localhost:11434"),
    "api_key": None,
    "ollama_timeout": int(os.environ.get("PENTRON_OLLAMA_TIMEOUT", 600)),
    "summary_timeout": int(os.environ.get("PENTRON_SUMMARY_TIMEOUT", 120)),
    "scan_delay_seconds": int(os.environ.get("PENTRON_SCAN_DELAY", 0)),
    "user_agent": os.environ.get("PENTRON_USER_AGENT") or None,
    "subdomain_discovery_level": int(
        os.environ.get("PENTRON_SUBDOMAIN_DISCOVERY_LEVEL", 0)
    ),
}


def _ensure_settings_table(cursor):
    """
    Idempotent — lets settings work against an existing DB volume created
    before this table existed, without requiring a fresh `docker compose
    down -v`. docker/schema.sql covers fresh installs; this covers upgrades.
    """
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
          id               INT PRIMARY KEY DEFAULT 1,
          provider         VARCHAR(50)  DEFAULT 'ollama',
          model            VARCHAR(100) DEFAULT 'huihui_ai/qwen3.5-abliterated:9b',
          ollama_host      VARCHAR(255) DEFAULT NULL,
          api_key          VARCHAR(500) DEFAULT NULL,
          ollama_timeout   INT          DEFAULT 600,
          summary_timeout  INT          DEFAULT 120,
          scan_delay_seconds INT        DEFAULT 0,
          user_agent       VARCHAR(500) DEFAULT NULL,
          subdomain_discovery_level INT DEFAULT 0,
          updated_at       DATETIME     DEFAULT NULL
        )
    """)
    # upgrade path for DB volumes created before these columns existed
    cursor.execute(
        "ALTER TABLE settings ADD COLUMN IF NOT EXISTS scan_delay_seconds INT DEFAULT 0"
    )
    cursor.execute(
        "ALTER TABLE settings ADD COLUMN IF NOT EXISTS "
        "user_agent VARCHAR(500) DEFAULT NULL"
    )
    cursor.execute(
        "ALTER TABLE settings ADD COLUMN IF NOT EXISTS "
        "subdomain_discovery_level INT DEFAULT 0"
    )


def get_settings() -> dict:
    """Return the persisted settings row, merged over env-var defaults for
    any column that was never set."""
    conn = get_connection()
    c = conn.cursor(dictionary=True)
    _ensure_settings_table(c)
    c.execute("SELECT * FROM settings WHERE id = 1")
    row = c.fetchone()
    conn.close()

    settings = dict(_SETTINGS_DEFAULTS)
    if row:
        for key in _SETTINGS_DEFAULTS:
            if row.get(key) is not None:
                settings[key] = row[key]
    return settings


def save_settings(**fields) -> None:
    """Upsert the single settings row. Unknown keys are ignored."""
    allowed = set(_SETTINGS_DEFAULTS.keys())
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    c = conn.cursor()
    _ensure_settings_table(c)

    columns = list(updates.keys()) + ["updated_at"]
    values = list(updates.values()) + [now]
    placeholders = ", ".join(["%s"] * len(columns))
    update_clause = ", ".join(f"{col} = VALUES({col})" for col in columns)
    c.execute(
        f"INSERT INTO settings (id, {', '.join(columns)}) VALUES (1, {placeholders}) "
        f"ON DUPLICATE KEY UPDATE {update_clause}",
        values,
    )
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────


def print_history(rows):
    print("\n" + "─" * 65)
    print(f"{'SL#':<6} {'TARGET':<28} {'DATE':<22} {'STATUS'}")
    print("─" * 65)
    for row in rows:
        print(f"{row[0]:<6} {row[1]:<28} {str(row[2]):<22} {row[3]}")
    print()


def print_session(data: dict):
    h = data["history"]
    print(f"\n{'═' * 60}")
    print(f"  SL# {h[0]} | Target: {h[1]} | {h[2]} | {h[3]}")
    print(f"{'═' * 60}")

    print("\n[ VULNERABILITIES ]")
    if data["vulns"]:
        for v in data["vulns"]:
            print(
                f"  id={v[0]} | {v[2]} | Severity: {v[3]} | "
                f"Port: {v[4]} | Service: {v[5]}"
            )
            print(f"           {v[6]}")
    else:
        print("  None recorded.")

    print("\n[ FIXES ]")
    if data["fixes"]:
        for f in data["fixes"]:
            print(f"  id={f[0]} | vuln_id={f[2]} | [{f[4]}] {f[3]}")
    else:
        print("  None recorded.")

    print("\n[ SUGGESTED EXPLOIT PATHS ]")
    if data.get("suggestions"):
        for suggestion in data["suggestions"]:
            print(f"  {suggestion[2]} | Tool: {suggestion[4] or '-'}")
            print(f"           {suggestion[3]}")
    else:
        print("  None recorded.")

    print("\n[ AI-DISPATCHED TOOL CALLS ]")
    if data.get("tool_calls"):
        for call in data["tool_calls"]:
            state = "BLOCKED" if call[5] else "EXECUTED"
            print(f"  [{state}] {call[2]}: {call[3]}")
    else:
        print("  None executed.")

    print("\n[ SUMMARY ]")
    if data["summary"]:
        s = data["summary"]
        print(f"  Risk Level : {s[4]}")
        print(f"  Status     : {s[7] or 'complete'}")
        print(f"  Generated  : {s[5]}")
        if s[6]:
            print(f"  Summary    : {s[6]}")
        print(
            f"\n  AI Analysis:\n  {s[3][:500]}{'...' if len(str(s[3])) > 500 else ''}"
        )
    else:
        print("  None recorded.")
    print()


# ─────────────────────────────────────────────
# QUICK CONNECTION TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    try:
        conn = get_connection()
        print("[+] MariaDB connection successful.")
        print("[+] Database: pentron")
        conn.close()
    except Exception as e:
        print(f"[!] Connection failed: {e}")
