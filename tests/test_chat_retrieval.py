from pentron.ai.capabilities import ContextPolicy, ModelCapabilities
from pentron.ai.chat import ChatContext, load_chat_context
from pentron.ai.chat.context import estimate_tokens


def _policy(session_budget=300):
    return ContextPolicy(
        capabilities=ModelCapabilities(1_024, 128),
        output_reserve=128,
        safety_margin=64,
        compression_threshold=0.75,
        session_context_budget=session_budget,
        history_budget=400,
        summary_budget=100,
    )


def _session():
    return {
        "history": {"sl_no": 7, "target": "example.com"},
        "summary": {
            "sl_no": 7,
            "risk_level": "HIGH",
            "short_summary": "Web findings need attention.",
        },
        "vulnerabilities": [
            {
                "id": 12,
                "sl_no": 7,
                "vuln_name": "Missing HSTS",
                "severity": "medium",
                "port": "443",
                "service": "https",
                "description": "Strict-Transport-Security header was absent.",
            },
            {
                "id": 11,
                "sl_no": 7,
                "vuln_name": "SQL injection",
                "severity": "critical",
                "port": "443",
                "service": "https",
                "description": "A quote changed the response body.",
            },
        ],
        "fixes": [
            {
                "id": 2,
                "sl_no": 7,
                "vuln_id": 12,
                "fix_text": "Enable HSTS with an appropriate max-age.",
            },
            {
                "id": 1,
                "sl_no": 7,
                "vuln_id": 11,
                "fix_text": "Use parameterized queries.",
            },
        ],
    }


def test_retrieval_focuses_on_current_question_and_keeps_grounding():
    context = load_chat_context(
        _session(), 7, "How should we remediate the missing HSTS header?", _policy()
    )

    assert isinstance(context, ChatContext)
    assert [finding.id for finding in context.findings] == [12]
    assert context.findings[0].evidence == (
        "Strict-Transport-Security header was absent."
    )
    assert context.findings[0].remediation == (
        "Enable HSTS with an appropriate max-age.",
    )


def test_retrieval_is_deterministic_for_equal_relevance():
    data = _session()

    first = load_chat_context(data, 7, "https port 443", _policy())
    second = load_chat_context(data, 7, "https port 443", _policy())

    assert first == second
    assert [finding.id for finding in first.findings] == [11, 12]


def test_retrieval_filters_cross_session_rows_and_relational_fixes():
    data = _session()
    data["vulnerabilities"].append(
        {
            "id": 99,
            "sl_no": 8,
            "vuln_name": "HSTS from another session",
            "description": "must not leak",
        }
    )
    data["fixes"].extend(
        [
            {
                "id": 3,
                "sl_no": 8,
                "vuln_id": 12,
                "fix_text": "cross-session remediation",
            },
            {
                "id": 4,
                "sl_no": 7,
                "vuln_id": 99,
                "fix_text": "orphan remediation",
            },
        ]
    )

    context = load_chat_context(data, 7, "HSTS", _policy())
    rendered = context.render(_policy().session_context_budget)

    assert [finding.id for finding in context.findings] == [12]
    assert "cross-session" not in rendered
    assert "orphan" not in rendered
    assert "must not leak" not in rendered


def test_retrieval_uses_safe_fallback_for_missing_or_unmatched_data():
    missing = load_chat_context({}, 7, "anything", _policy())
    unmatched = load_chat_context(_session(), 7, "certificate expiry", _policy())

    assert missing.findings == ()
    assert missing.fallback == "Session data unavailable."
    assert unmatched.findings == ()
    assert "No session findings matched" in unmatched.fallback


def test_retrieval_render_observes_context_policy_budget():
    data = _session()
    data["vulnerabilities"][0]["description"] = "evidence " * 2_000
    data["fixes"][0]["fix_text"] = "remediation " * 2_000
    policy = _policy(session_budget=80)

    rendered = load_chat_context(data, 7, "HSTS", policy).render(
        policy.session_context_budget
    )

    assert estimate_tokens(rendered) <= policy.session_context_budget
    assert "Finding #12" in rendered
