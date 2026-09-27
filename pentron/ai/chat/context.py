"""Bounded scan context and conversation normalization helpers."""

import math
import re

CHAT_SEED_BUDGET = 2_000
TOKEN_CHAR_RATIO = 4
MAX_SEED_CHARS = CHAT_SEED_BUDGET * TOKEN_CHAR_RATIO
MAX_TARGET_CHARS = 500
MAX_SUMMARY_CHARS = 1_200
MAX_RISK_LEVEL_CHARS = 50
MAX_FINDING_NAME_CHARS = 200
MAX_SEVERITY_CHARS = 50
MAX_PORT_CHARS = 20
MAX_SERVICE_CHARS = 100
OMITTED_FINDINGS_NOTICE = "[Additional findings omitted due to context limit]"
_TRUNCATION_SUFFIX = "…"
ALLOWED_CHAT_ROLES = frozenset({"user", "assistant"})
MAX_CHAT_MESSAGE_CHARS = 8_000
CHAT_MESSAGE_OVERHEAD = 4


def estimate_tokens(text: str | None) -> int:
    if not isinstance(text, str):
        return 0
    text = text.strip()
    return math.ceil(len(text) / TOKEN_CHAR_RATIO) if text else 0


def truncate_to_tokens(text: str, max_tokens: int) -> str:
    """Return a deterministic prefix that fits the approximate token budget."""
    if not isinstance(text, str) or max_tokens <= 0:
        return ""
    return text[: max_tokens * TOKEN_CHAR_RATIO].rstrip()


def _compact(value, max_chars: int | None = None) -> str:
    if value is None:
        return ""
    text = re.sub(r"\s+", " ", str(value)).strip()
    if not text or max_chars is None or len(text) <= max_chars:
        return text
    if max_chars <= 0:
        return ""
    if max_chars <= len(_TRUNCATION_SUFFIX):
        return _TRUNCATION_SUFFIX[:max_chars]
    return text[: max_chars - len(_TRUNCATION_SUFFIX)].rstrip() + _TRUNCATION_SUFFIX


def _append_if_value(lines, label, value, max_chars=None) -> None:
    if text := _compact(value, max_chars):
        lines.append(f"{label}: {text}")


def _format_fields(data: dict, fields: list[tuple[str, str, int | None]]) -> str:
    parts = []
    for key, label, max_chars in fields:
        if text := _compact(data.get(key), max_chars):
            parts.append(f"{label}: {text}" if label else text)
    return " | ".join(parts)


def build_seed_context(session_data: dict, max_chars: int = MAX_SEED_CHARS) -> str:
    if not isinstance(session_data, dict) or not session_data or max_chars <= 0:
        return ""

    lines = ["SCAN SESSION CONTEXT"]
    history = session_data.get("history") or {}
    _append_if_value(lines, "Target", history.get("target"), MAX_TARGET_CHARS)
    summary = session_data.get("summary") or {}
    _append_if_value(
        lines, "Risk Level", summary.get("risk_level"), MAX_RISK_LEVEL_CHARS
    )
    _append_if_value(
        lines, "Short Summary", summary.get("short_summary"), MAX_SUMMARY_CHARS
    )
    lines.append("FINDINGS")
    fields = [
        ("vuln_name", "", MAX_FINDING_NAME_CHARS),
        ("severity", "Severity", MAX_SEVERITY_CHARS),
        ("port", "Port", MAX_PORT_CHARS),
        ("service", "Service", MAX_SERVICE_CHARS),
    ]
    seed_context = "\n".join(lines) + "\n"
    if len(seed_context) > max_chars:
        return seed_context[:max_chars].rstrip()

    findings = [
        finding
        for vuln in session_data.get("vulnerabilities") or []
        if isinstance(vuln, dict) and (finding := _format_fields(vuln, fields))
    ]
    if not findings:
        no_findings = "None reported"
        if len(seed_context) + len(no_findings) <= max_chars:
            seed_context += no_findings
        return seed_context.rstrip()

    for index, finding in enumerate(findings):
        separator = "" if seed_context.endswith("\n") else "\n"
        candidate = seed_context + separator + finding
        has_more = index < len(findings) - 1
        notice_reserve = 1 + len(OMITTED_FINDINGS_NOTICE) if has_more else 0
        if len(candidate) + notice_reserve > max_chars:
            notice = seed_context + separator + OMITTED_FINDINGS_NOTICE
            if len(notice) <= max_chars:
                seed_context = notice
            break
        seed_context = candidate
    return seed_context.rstrip()


def normalize_history(history) -> list[dict[str, str]]:
    if not isinstance(history, list):
        return []
    normalized = []
    for entry in history:
        if not isinstance(entry, dict):
            continue
        role, content = entry.get("role"), entry.get("content")
        if role not in ALLOWED_CHAT_ROLES or not isinstance(content, str):
            continue
        content = content.strip()
        if content:
            normalized.append(
                {"role": role, "content": content[:MAX_CHAT_MESSAGE_CHARS]}
            )
    return normalized


def estimate_history_tokens(history: list[dict[str, str]]) -> int:
    return sum(
        estimate_tokens(message["content"]) + CHAT_MESSAGE_OVERHEAD
        for message in normalize_history(history)
    )


def estimate_message_tokens(messages: list[dict[str, str]]) -> int:
    """Estimate any provider message list, including privileged roles."""
    return sum(
        estimate_tokens(message.get("content")) + CHAT_MESSAGE_OVERHEAD
        for message in messages
        if isinstance(message, dict) and isinstance(message.get("content"), str)
    )


def bound_history_by_tokens(
    history: list[dict[str, str]], max_tokens: int
) -> list[dict[str, str]]:
    """Keep the newest messages that fit, truncating only the newest if needed."""
    if max_tokens <= CHAT_MESSAGE_OVERHEAD:
        return []
    kept = []
    remaining = max_tokens
    for message in reversed(normalize_history(history)):
        content_budget = remaining - CHAT_MESSAGE_OVERHEAD
        if content_budget <= 0:
            break
        content_tokens = estimate_tokens(message["content"])
        if content_tokens <= content_budget:
            kept.append(message)
            remaining -= content_tokens + CHAT_MESSAGE_OVERHEAD
            continue
        if kept:
            break
        content = truncate_to_tokens(message["content"], content_budget)
        if content:
            kept.append({"role": message["role"], "content": content})
        break
    return list(reversed(kept))
