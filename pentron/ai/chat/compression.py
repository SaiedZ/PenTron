"""Conversation compression policy for session chat."""

from ..prompts import CHAT_COMPRESSION_SYSTEM_PROMPT
from .context import estimate_history_tokens, estimate_tokens, normalize_history

CHAT_CONTEXT_BUDGET = 16_000
CHAT_RESPONSE_RESERVE = 2_000
CHAT_COMPRESSION_THRESHOLD = 0.75
CHAT_RECENT_MESSAGES = 6
CHAT_COMPRESSION_MAX_TOKENS = 800
CONVERSATION_SUMMARY_PREFIX = "[Conversation summary]\n"


def maybe_compress(
    history,
    provider,
    *,
    fixed_context: str = "",
    budget: int = CHAT_CONTEXT_BUDGET,
    response_reserve: int = CHAT_RESPONSE_RESERVE,
) -> list[dict[str, str]]:
    normalized = normalize_history(history)
    total_tokens = (
        estimate_tokens(fixed_context)
        + estimate_history_tokens(normalized)
        + max(0, response_reserve)
    )
    if (
        total_tokens < max(0, budget) * CHAT_COMPRESSION_THRESHOLD
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
            max_tokens=CHAT_COMPRESSION_MAX_TOKENS,
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
