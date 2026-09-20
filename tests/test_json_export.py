import json
from copy import deepcopy
from datetime import UTC, datetime
from unittest.mock import Mock

from api.routers import exports
from pentron.export import build_json_export, json_export_filename


def _serialized_session():
    return {
        "history": {"sl_no": 7, "target": "https://example.com", "status": "done"},
        "summary": {
            "short_summary": "One medium finding",
            "risk_level": "MEDIUM",
            "raw_scan": "sensitive raw output",
            "ai_analysis": "long analysis",
        },
        "vulnerabilities": [{"vuln_name": "Missing header"}],
        "fixes": [],
        "exploits": [],
        "suggestions": [],
        "tool_calls": [],
    }


def _database_session():
    return {
        "history": (7, "https://example.com", None, "done"),
        "vulns": [],
        "fixes": [],
        "exploits": [],
        "summary": (
            1,
            7,
            "raw",
            "analysis",
            "MEDIUM",
            None,
            "short",
            "complete",
            None,
        ),
        "suggestions": [],
        "tool_calls": [],
    }


def test_standard_json_export_excludes_raw_fields_and_has_metadata():
    exported = build_json_export(
        _serialized_session(),
        exported_at=datetime(2026, 9, 20, 12, 30, tzinfo=UTC),
    )

    assert exported["schema_version"] == 1
    assert exported["exported_at"] == "2026-09-20T12:30:00Z"
    assert exported["includes_raw_data"] is False
    assert exported["session"]["summary"] == {
        "short_summary": "One medium finding",
        "risk_level": "MEDIUM",
    }


def test_complete_json_export_includes_raw_fields():
    exported = build_json_export(_serialized_session(), include_raw=True)

    assert exported["includes_raw_data"] is True
    assert exported["session"]["summary"]["raw_scan"] == "sensitive raw output"
    assert exported["session"]["summary"]["ai_analysis"] == "long analysis"


def test_json_export_does_not_mutate_session():
    session = _serialized_session()
    original = deepcopy(session)

    build_json_export(session)

    assert session == original


def test_json_export_handles_missing_summary():
    session = _serialized_session()
    session["summary"] = None

    assert build_json_export(session)["session"]["summary"] is None


def test_json_filename_is_safe_and_ascii_only():
    filename = json_export_filename(7, "https://tést.example/path\r\nheader")

    assert filename == "pentron_SL7_https_tst_example_path_header.json"
    assert filename.isascii()
    assert "\r" not in filename
    assert "\n" not in filename


def test_json_endpoint_returns_download_without_raw_data(monkeypatch):
    monkeypatch.setattr(
        exports.db, "get_session", Mock(return_value=_database_session())
    )

    response = exports.export_session(7, format="json", include_raw=False)
    payload = json.loads(response.body)

    assert response.media_type == "application/json"
    assert response.headers["content-disposition"] == (
        'attachment; filename="pentron_SL7_https_example_com.json"'
    )
    assert "raw_scan" not in payload["session"]["summary"]
    assert "ai_analysis" not in payload["session"]["summary"]


def test_json_endpoint_can_return_complete_export(monkeypatch):
    monkeypatch.setattr(
        exports.db, "get_session", Mock(return_value=_database_session())
    )

    response = exports.export_session(7, format="json", include_raw=True)
    payload = json.loads(response.body)

    assert payload["session"]["summary"]["raw_scan"] == "raw"
    assert payload["session"]["summary"]["ai_analysis"] == "analysis"
