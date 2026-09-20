import math
import re

CHAT_CONTEXT_BUDGET = 16_000
CHAT_RESPONSE_RESERVE = 2_000
CHAT_COMPRESSION_THRESHOLD = 0.75

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

CHAT_SYSTEM_PROMPT = """
You are PenTron's session assistant.

You answer questions about one authorized security scan.

Rules:
- Answer in the language used by the user's first message when possible.
- Use only the provided session context and conversation history.
- Never claim to have seen raw scan output or details absent from the context.
- If information is missing, say so explicitly.
- Do not execute or request tools, searches, scans, or network operations.
- Never emit [TOOL:] or [SEARCH:] instructions.
- Use concise Markdown: short headings, paragraphs, lists, inline code,
  and fenced code blocks.
- Do not output raw HTML.
- Clearly distinguish confirmed findings from hypotheses.
""".strip()


def estimate_tokens(text: str | None) -> int:
    """Estimate a text's token count without provider-specific dependencies."""

    if not isinstance(text, str):
        return 0

    text = text.strip()
    if not text:
        return 0

    return math.ceil(len(text) / TOKEN_CHAR_RATIO)


def _compact(value, max_chars: int | None = None) -> str:
    """Normalize a value into a compact single-line string."""

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


def _append_if_value(
    lines: list[str],
    label: str,
    value,
    max_chars: int | None = None,
) -> None:
    """Append a labeled value when present."""

    if text := _compact(value, max_chars):
        lines.append(f"{label}: {text}")


def _format_fields(
    data: dict,
    fields: list[tuple[str, str, int | None]],
) -> str:
    """Format selected fields into a compact single-line string."""

    parts = []

    for key, label, max_chars in fields:
        if text := _compact(data.get(key), max_chars):
            parts.append(f"{label}: {text}" if label else text)

    return " | ".join(parts)


def build_seed_context(
    session_data: dict,
    max_chars: int = MAX_SEED_CHARS,
) -> str:
    """Build a compact, bounded description of a scan session."""

    if not isinstance(session_data, dict) or not session_data:
        return ""

    if max_chars <= 0:
        return ""

    lines = ["SCAN SESSION CONTEXT"]

    history = session_data.get("history") or {}
    _append_if_value(
        lines,
        "Target",
        history.get("target"),
        MAX_TARGET_CHARS,
    )

    summary = session_data.get("summary") or {}
    _append_if_value(
        lines,
        "Risk Level",
        summary.get("risk_level"),
        MAX_RISK_LEVEL_CHARS,
    )
    _append_if_value(
        lines,
        "Short Summary",
        summary.get("short_summary"),
        MAX_SUMMARY_CHARS,
    )

    lines.append("FINDINGS")

    vulnerability_fields = [
        ("vuln_name", "", MAX_FINDING_NAME_CHARS),
        ("severity", "Severity", MAX_SEVERITY_CHARS),
        ("port", "Port", MAX_PORT_CHARS),
        ("service", "Service", MAX_SERVICE_CHARS),
    ]

    seed_context = "\n".join(lines) + "\n"

    if len(seed_context) > max_chars:
        return seed_context[:max_chars].rstrip()

    findings = []

    for vuln in session_data.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue

        if finding := _format_fields(vuln, vulnerability_fields):
            findings.append(finding)

    if not findings:
        no_findings = "None reported"
        if len(seed_context) + len(no_findings) <= max_chars:
            seed_context += no_findings
        return seed_context.rstrip()

    for index, finding in enumerate(findings):
        separator = "" if seed_context.endswith("\n") else "\n"
        candidate = seed_context + separator + finding
        has_more_findings = index < len(findings) - 1
        notice_reserve = 1 + len(OMITTED_FINDINGS_NOTICE) if has_more_findings else 0

        if len(candidate) + notice_reserve > max_chars:
            notice = seed_context + separator + OMITTED_FINDINGS_NOTICE
            if len(notice) <= max_chars:
                seed_context = notice
            break

        seed_context = candidate

    return seed_context.rstrip()


def normalize_history(history) -> list[dict[str, str]]:
    """Return a safe copy of a client-provided conversation history."""
    if not isinstance(history, list):
        return []

    normalized_history = []
    for entry in history:
        if not isinstance(entry, dict):
            continue

        role = entry.get("role")
        content = entry.get("content")

        if role not in ALLOWED_CHAT_ROLES or not isinstance(content, str):
            continue

        content = content.strip()
        if not content:
            continue

        normalized_history.append(
            {"role": role, "content": content[:MAX_CHAT_MESSAGE_CHARS]}
        )

    return normalized_history


def estimate_history_tokens(history: list[dict[str, str]]) -> int:
    """Estimate conversation tokens, including per-message structure."""
    return sum(
        estimate_tokens(message["content"]) + CHAT_MESSAGE_OVERHEAD
        for message in normalize_history(history)
    )
