"""Token-budgeted conversation memory and compression."""

from dataclasses import dataclass

from ..capabilities import ContextPolicy, context_policy_for
from ..prompts import CHAT_COMPRESSION_SYSTEM_PROMPT
from .context import (
    CHAT_MESSAGE_OVERHEAD,
    bound_history_by_tokens,
    estimate_history_tokens,
    estimate_tokens,
    normalize_history,
    truncate_to_tokens,
)

CONVERSATION_SUMMARY_PREFIX = "[Conversation summary]\n"


@dataclass(frozen=True)
class ConversationMemory:
    """Conversation categories kept separate for independent budgeting."""

    summary: str
    history: list[dict[str, str]]

    def as_history(self) -> list[dict[str, str]]:
        if not self.summary:
            return list(self.history)
        return [
            {
                "role": "assistant",
                "content": CONVERSATION_SUMMARY_PREFIX + self.summary,
            },
            *self.history,
        ]


def split_memory(history) -> ConversationMemory:
    """Decode the API-compatible history representation into memory categories."""
    summaries = []
    recent = []
    for message in normalize_history(history):
        content = message["content"]
        if content.startswith(CONVERSATION_SUMMARY_PREFIX):
            summary = content.removeprefix(CONVERSATION_SUMMARY_PREFIX).strip()
            if summary:
                summaries.append(summary)
        else:
            recent.append(message)
    return ConversationMemory("\n".join(summaries), recent)


def maybe_compress(
    history,
    provider,
    *,
    policy: ContextPolicy | None = None,
) -> ConversationMemory:
    policy = policy or context_policy_for(provider)
    memory = split_memory(history)
    summary_content_budget = max(0, policy.summary_budget - CHAT_MESSAGE_OVERHEAD)
    bounded_summary = truncate_to_tokens(memory.summary, summary_content_budget)
    history_tokens = estimate_history_tokens(memory.history)
    trigger = int(policy.history_budget * policy.compression_threshold)
    bounded_history = bound_history_by_tokens(memory.history, policy.history_budget)
    if history_tokens < trigger:
        return ConversationMemory(
            bounded_summary,
            bounded_history,
        )

    kept_tokens = max(1, trigger)
    recent_messages = bound_history_by_tokens(memory.history, kept_tokens)
    old_count = len(memory.history) - len(recent_messages)
    if old_count <= 0 or summary_content_budget <= 0:
        return ConversationMemory(bounded_summary, bounded_history)
    old_messages = memory.history[:old_count]
    transcript = "\n".join(
        f"{message['role'].upper()}: {message['content']}" for message in old_messages
    )
    if memory.summary:
        transcript = f"PREVIOUS SUMMARY: {memory.summary}\n{transcript}"
    user_prefix = "Conversation to summarize:\n\n"
    transcript_budget = max(
        0,
        policy.input_budget
        - estimate_tokens(CHAT_COMPRESSION_SYSTEM_PROMPT)
        - estimate_tokens(user_prefix)
        - (2 * CHAT_MESSAGE_OVERHEAD),
    )
    transcript = truncate_to_tokens(transcript, transcript_budget)
    if not transcript:
        return ConversationMemory(bounded_summary, bounded_history)
    try:
        response = provider.send(
            [
                {"role": "system", "content": CHAT_COMPRESSION_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": user_prefix + transcript,
                },
            ],
            max_tokens=policy.summary_budget,
            temperature=0.2,
        )
    except Exception:
        return ConversationMemory(bounded_summary, bounded_history)

    summary = getattr(response, "text", "")
    if not isinstance(summary, str):
        return ConversationMemory(bounded_summary, bounded_history)
    summary = summary.strip()
    if not summary or summary.startswith("[!]"):
        return ConversationMemory(bounded_summary, bounded_history)
    summary = truncate_to_tokens(summary, summary_content_budget)
    return ConversationMemory(
        summary,
        bound_history_by_tokens(recent_messages, policy.history_budget),
    )
