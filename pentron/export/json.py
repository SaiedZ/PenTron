"""Versioned JSON export for serialized scan sessions."""

import re
from copy import deepcopy
from datetime import UTC, datetime

JSON_EXPORT_SCHEMA_VERSION = 1


def build_json_export(
    session: dict,
    *,
    include_raw: bool = False,
    exported_at: datetime | None = None,
) -> dict:
    """Build a versioned export without mutating the serialized session."""
    exported_session = deepcopy(session)
    summary = exported_session.get("summary")

    if isinstance(summary, dict) and not include_raw:
        summary.pop("raw_scan", None)
        summary.pop("ai_analysis", None)

    timestamp = exported_at or datetime.now(UTC)
    return {
        "schema_version": JSON_EXPORT_SCHEMA_VERSION,
        "exported_at": timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "includes_raw_data": include_raw,
        "session": exported_session,
    }


def json_export_filename(sl_no: int, target: str) -> str:
    """Return an ASCII-safe download filename for a session export."""
    safe_target = str(target or "session").encode("ascii", "ignore").decode()
    safe_target = re.sub(r"[^A-Za-z0-9_-]+", "_", safe_target).strip("_")
    return f"pentron_SL{sl_no}_{safe_target or 'session'}.json"
