"""Deterministic, session-scoped context retrieval for scan chat."""

import re
from dataclasses import dataclass

from ..capabilities import ContextPolicy
from .context import estimate_tokens, truncate_to_tokens

_WORD_RE = re.compile(r"[a-z0-9][a-z0-9._:/-]*", re.IGNORECASE)
_STOP_WORDS = frozenset(
    {
        "a",
        "about",
        "and",
        "are",
        "can",
        "explain",
        "for",
        "how",
        "is",
        "it",
        "me",
        "of",
        "please",
        "the",
        "this",
        "to",
        "what",
        "why",
    }
)
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_FALLBACK = "No session findings matched the current question."


@dataclass(frozen=True)
class ChatFinding:
    """One finding plus remediation resolved through its relational ID."""

    id: int
    name: str
    severity: str
    port: str
    service: str
    evidence: str
    remediation: tuple[str, ...]


@dataclass(frozen=True)
class ChatContext:
    """Typed context selected for one question in one scan session."""

    session_id: int
    target: str
    risk_level: str
    summary: str
    findings: tuple[ChatFinding, ...]
    fallback: str = ""

    def render(self, max_tokens: int) -> str:
        """Render without exceeding the context-policy token allocation."""
        if max_tokens <= 0:
            return ""
        lines = ["SCAN SESSION CONTEXT", f"Session ID: {self.session_id}"]
        if self.target:
            lines.append(f"Target: {self.target}")
        if self.risk_level:
            lines.append(f"Risk Level: {self.risk_level}")
        if self.summary:
            lines.append(f"Short Summary: {self.summary}")
        lines.append("RELEVANT FINDINGS")
        if self.fallback:
            lines.append(self.fallback)
        for finding in self.findings:
            fixes = "; ".join(finding.remediation) or "Not recorded"
            block = (
                f"Finding #{finding.id}: {finding.name}\n"
                f"Severity: {finding.severity} | Port: {finding.port or 'N/A'} | "
                f"Service: {finding.service or 'N/A'}\n"
                f"Evidence: {finding.evidence or 'Not recorded'}\n"
                f"Remediation: {fixes}"
            )
            candidate = "\n".join([*lines, block])
            if estimate_tokens(candidate) <= max_tokens:
                lines.append(block)
                continue
            remaining = max_tokens - estimate_tokens("\n".join(lines))
            if remaining > 16:
                lines.append(truncate_to_tokens(block, remaining))
            break
        return truncate_to_tokens("\n".join(lines), max_tokens)


def _text(value) -> str:
    return str(value).strip() if value is not None else ""


def _session_id(item: dict) -> int | None:
    try:
        return int(item.get("sl_no"))
    except (TypeError, ValueError):
        return None


def _terms(text: str) -> set[str]:
    return {
        token.lower()
        for token in _WORD_RE.findall(text)
        if len(token) > 1 and token.lower() not in _STOP_WORDS
    }


def _score(finding: ChatFinding, question_terms: set[str]) -> int:
    weighted_fields = (
        (finding.name, 6),
        (finding.service, 4),
        (finding.port, 4),
        (finding.evidence, 2),
        (" ".join(finding.remediation), 1),
        (finding.severity, 1),
    )
    return sum(
        weight * len(question_terms & _terms(value))
        for value, weight in weighted_fields
    )


def load_chat_context(
    session_data: dict,
    session_id: int,
    question: str,
    policy: ContextPolicy,
) -> ChatContext:
    """Load relevant findings, strictly filtering and joining on relational IDs."""
    history = session_data.get("history") or {}
    if not isinstance(history, dict) or _session_id(history) != session_id:
        return ChatContext(session_id, "", "", "", (), "Session data unavailable.")

    fixes_by_vulnerability: dict[int, list[str]] = {}
    for fix in session_data.get("fixes") or []:
        if not isinstance(fix, dict) or _session_id(fix) != session_id:
            continue
        try:
            vulnerability_id = int(fix.get("vuln_id"))
        except (TypeError, ValueError):
            continue
        fix_text = _text(fix.get("fix_text"))
        if fix_text:
            fixes_by_vulnerability.setdefault(vulnerability_id, []).append(fix_text)

    findings = []
    for item in session_data.get("vulnerabilities") or []:
        if not isinstance(item, dict) or _session_id(item) != session_id:
            continue
        try:
            finding_id = int(item.get("id"))
        except (TypeError, ValueError):
            continue
        findings.append(
            ChatFinding(
                id=finding_id,
                name=_text(item.get("vuln_name")),
                severity=_text(item.get("severity")),
                port=_text(item.get("port")),
                service=_text(item.get("service")),
                evidence=_text(item.get("description")),
                remediation=tuple(fixes_by_vulnerability.get(finding_id, ())),
            )
        )

    question_terms = _terms(question)
    ranked = [
        (score, finding)
        for finding in findings
        if (score := _score(finding, question_terms)) > 0
    ]
    ranked.sort(
        key=lambda item: (
            -item[0],
            _SEVERITY_ORDER.get(item[1].severity.lower(), 4),
            item[1].id,
        )
    )
    summary = session_data.get("summary") or {}
    if not isinstance(summary, dict) or _session_id(summary) != session_id:
        summary = {}
    context = ChatContext(
        session_id=session_id,
        target=_text(history.get("target")),
        risk_level=_text(summary.get("risk_level")),
        summary=_text(summary.get("short_summary")),
        findings=tuple(finding for _, finding in ranked),
        fallback="" if ranked else _FALLBACK,
    )
    if not context.render(policy.session_context_budget):
        return ChatContext(session_id, "", "", "", (), "Session data unavailable.")
    return context
