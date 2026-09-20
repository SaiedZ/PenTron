from pentron.chat import (
    OMITTED_FINDINGS_NOTICE,
    CHAT_SYSTEM_PROMPT,
    _append_if_value,
    _compact,
    _format_fields,
    build_seed_context,
    estimate_tokens,
)


def test_estimate_tokens():
    assert estimate_tokens(None) == 0
    assert estimate_tokens("") == 0
    assert estimate_tokens("   ") == 0
    assert estimate_tokens("a") == 1
    assert estimate_tokens("abcd") == 1
    assert estimate_tokens("abcde") == 2
    assert estimate_tokens("abcdefgh") == 2
    assert estimate_tokens("abcdefghi") == 3


def test_compact():
    assert _compact(None) == ""
    assert _compact("") == ""
    assert _compact("   ") == ""
    assert _compact("  hello   world  ") == "hello world"
    assert _compact("hello\nworld\tfoo") == "hello world foo"


def test_compact_truncates_value():
    result = _compact("abcdefghij", 5)

    assert result == "abcd…"
    assert len(result) == 5


def test_compact_respects_small_limits():
    assert _compact("abc", 0) == ""
    assert _compact("abc", 1) == "…"


def test_append_if_value():
    lines = []

    _append_if_value(lines, "Target", "example.com")
    _append_if_value(lines, "Empty", "")
    _append_if_value(lines, "None", None)

    assert lines == ["Target: example.com"]


def test_append_if_value_compacts_and_truncates():
    lines = []

    _append_if_value(
        lines,
        "Summary",
        "  foo\nbar    baz  ",
        max_chars=7,
    )

    assert lines == ["Summary: foo ba…"]


def test_format_fields():
    data = {
        "name": "SQL Injection",
        "severity": "High",
        "port": 443,
        "service": "https",
    }

    fields = [
        ("name", "", 200),
        ("severity", "Severity", 50),
        ("port", "Port", 20),
        ("service", "Service", 100),
    ]

    assert _format_fields(data, fields) == (
        "SQL Injection | Severity: High | Port: 443 | Service: https"
    )


def test_format_fields_ignores_missing_values():
    data = {
        "name": "Open Port",
        "port": 22,
    }

    fields = [
        ("name", "", 200),
        ("severity", "Severity", 50),
        ("port", "Port", 20),
        ("service", "Service", 100),
    ]

    assert _format_fields(data, fields) == "Open Port | Port: 22"


def test_format_fields_compacts_and_truncates_values():
    data = {
        "name": "Very   long\nfinding name",
        "severity": "High",
    }

    fields = [
        ("name", "", 10),
        ("severity", "Severity", 50),
    ]

    assert _format_fields(data, fields) == ("Very long… | Severity: High")


def test_format_fields_returns_empty_string_when_no_values():
    fields = [
        ("name", "", 200),
        ("severity", "Severity", 50),
    ]

    assert _format_fields({}, fields) == ""


def test_build_seed_context():
    session_data = {
        "history": {
            "target": "example.com",
        },
        "summary": {
            "risk_level": "High",
            "short_summary": "Multiple vulnerabilities found",
        },
        "vulnerabilities": [
            {
                "vuln_name": "SQL Injection",
                "severity": "High",
                "port": 443,
                "service": "https",
            },
            {
                "vuln_name": "Open SSH",
                "severity": "Medium",
                "port": 22,
                "service": "ssh",
            },
        ],
    }

    assert build_seed_context(session_data) == (
        "SCAN SESSION CONTEXT\n"
        "Target: example.com\n"
        "Risk Level: High\n"
        "Short Summary: Multiple vulnerabilities found\n"
        "FINDINGS\n"
        "SQL Injection | Severity: High | Port: 443 | Service: https\n"
        "Open SSH | Severity: Medium | Port: 22 | Service: ssh"
    )


def test_build_seed_context_empty_data():
    assert build_seed_context({}) == ""


def test_build_seed_context_without_findings():
    session_data = {"history": {"target": "example.com"}, "vulnerabilities": []}

    result = build_seed_context(session_data)

    assert result.endswith("FINDINGS\nNone reported")


def test_build_seed_context_invalid_max_chars():
    session_data = {"vulnerabilities": []}

    assert build_seed_context(session_data, max_chars=0) == ""
    assert build_seed_context(session_data, max_chars=-1) == ""


def test_build_seed_context_ignores_invalid_vulnerabilities():
    session_data = {
        "vulnerabilities": [
            None,
            "invalid",
            {},
            {"vuln_name": "Valid finding"},
        ],
    }

    assert build_seed_context(session_data) == (
        "SCAN SESSION CONTEXT\nFINDINGS\nValid finding"
    )


def test_build_seed_context_compacts_values():
    session_data = {
        "history": {
            "target": "  example.com\n ",
        },
        "summary": {
            "risk_level": "  High ",
            "short_summary": "Multiple\n\n vulnerabilities   found",
        },
        "vulnerabilities": [
            {
                "vuln_name": "SQL\n Injection",
                "service": "  https  ",
            },
        ],
    }

    assert build_seed_context(session_data) == (
        "SCAN SESSION CONTEXT\n"
        "Target: example.com\n"
        "Risk Level: High\n"
        "Short Summary: Multiple vulnerabilities found\n"
        "FINDINGS\n"
        "SQL Injection | Service: https"
    )


def test_build_seed_context_adds_omitted_notice():
    base_context = "SCAN SESSION CONTEXT\nFINDINGS\n"

    session_data = {
        "vulnerabilities": [
            {"vuln_name": "First finding"},
            {"vuln_name": "S" * 100},
        ],
    }

    max_chars = (
        len(base_context) + len("First finding\n") + len(OMITTED_FINDINGS_NOTICE)
    )

    result = build_seed_context(session_data, max_chars=max_chars)

    assert (
        result == (base_context + "First finding\n" + OMITTED_FINDINGS_NOTICE).rstrip()
    )

    assert len(result) <= max_chars


def test_build_seed_context_notice_must_fit():
    base_context = "SCAN SESSION CONTEXT\nFINDINGS\n"

    session_data = {
        "vulnerabilities": [
            {"vuln_name": "A" * 100},
            {"vuln_name": "Second finding"},
        ],
    }

    max_chars = len(base_context) + 10

    result = build_seed_context(session_data, max_chars=max_chars)

    assert OMITTED_FINDINGS_NOTICE not in result
    assert len(result) <= max_chars


def test_build_seed_context_does_not_reserve_notice_for_last_finding():
    base_context = "SCAN SESSION CONTEXT\nFINDINGS\n"
    finding = "Last finding"

    session_data = {
        "vulnerabilities": [
            {"vuln_name": finding},
        ],
    }

    max_chars = len(base_context) + len(finding)

    result = build_seed_context(session_data, max_chars=max_chars)

    assert result == base_context + finding
    assert OMITTED_FINDINGS_NOTICE not in result
    assert len(result) <= max_chars


def test_build_seed_context_never_exceeds_max_chars():
    session_data = {
        "history": {
            "target": "example.com",
        },
        "summary": {
            "short_summary": "A" * 10_000,
        },
        "vulnerabilities": [{"vuln_name": "B" * 1_000} for _ in range(100)],
    }

    max_chars = 500

    result = build_seed_context(session_data, max_chars=max_chars)

    assert len(result) <= max_chars
    assert estimate_tokens(result) <= max_chars // 4


def test_build_seed_context_excludes_verbose_session_data():
    session_data = {
        "history": {"target": "example.com"},
        "summary": {
            "short_summary": "Compact summary",
            "raw_scan": "SECRET RAW SCAN",
            "ai_analysis": "SECRET FULL ANALYSIS",
        },
        "vulnerabilities": [
            {
                "vuln_name": "Missing HSTS",
                "description": "SECRET LONG DESCRIPTION",
            }
        ],
    }

    result = build_seed_context(session_data)

    assert "Missing HSTS" in result
    assert "SECRET RAW SCAN" not in result
    assert "SECRET FULL ANALYSIS" not in result
    assert "SECRET LONG DESCRIPTION" not in result


def test_chat_system_prompt_forbids_tools_and_unsupported_claims():
    prompt = CHAT_SYSTEM_PROMPT.lower()

    assert "[tool:]" in prompt
    assert "[search:]" in prompt
    assert "raw scan" in prompt
    assert "missing" in prompt
    assert "language" in prompt
