"""Conversation compression policy for session chat."""

from ..capabilities import ContextPolicy, context_policy_for
from ..prompts import CHAT_COMPRESSION_SYSTEM_PROMPT
from .context import estimate_history_tokens, estimate_tokens, normalize_history

CHAT_RECENT_MESSAGES = 6
CONVERSATION_SUMMARY_PREFIX = "[Conversation summary]\n"


def maybe_compress(
    history,
    provider,
    *,
    fixed_context: str = "",
    policy: ContextPolicy | None = None,
) -> list[dict[str, str]]:
    policy = policy or context_policy_for(provider)
    normalized = normalize_history(history)
    total_tokens = estimate_tokens(fixed_context) + estimate_history_tokens(normalized)
    if (
        total_tokens < policy.compression_trigger_tokens
        or len(normalized) <= CHAT_RECENT_MESSAGES
    ):
        return normalized

    old_messages = normalized[:-CHAT_RECENT_MESSAGES]
    recent_messages = normalized[-CHAT_RECENT_MESSAGES:]
    transcript = "\n".join(
        f"{message['role'].upper()}: {message['content']}" for message in old_messages
    )
    try:
        response = provider.send(
            [
                {"role": "system", "content": CHAT_COMPRESSION_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": f"Conversation to summarize:\n\n{transcript}",
                },
            ],
            max_tokens=policy.summary_budget,
            temperature=0.2,
        )
    except Exception:
        return normalized

    summary = getattr(response, "text", "")
    if not isinstance(summary, str):
        return normalized
    summary = summary.strip()
    if not summary or summary.startswith("[!]"):
        return normalized
    return [
        {"role": "assistant", "content": CONVERSATION_SUMMARY_PREFIX + summary},
        *recent_messages,
    ]
