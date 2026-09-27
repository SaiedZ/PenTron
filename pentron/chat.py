"""Temporary compatibility facade for :mod:`pentron.ai.chat`."""

from .ai.chat.compression import (
    CHAT_COMPRESSION_MAX_TOKENS,
    CHAT_COMPRESSION_THRESHOLD,
    CHAT_CONTEXT_BUDGET,
    CHAT_RECENT_MESSAGES,
    CHAT_RESPONSE_RESERVE,
    CONVERSATION_SUMMARY_PREFIX,
    maybe_compress,
)
from .ai.chat.context import (
    ALLOWED_CHAT_ROLES,
    CHAT_MESSAGE_OVERHEAD,
    CHAT_SEED_BUDGET,
    MAX_CHAT_MESSAGE_CHARS,
    MAX_SEED_CHARS,
    OMITTED_FINDINGS_NOTICE,
    TOKEN_CHAR_RATIO,
    _append_if_value,
    _compact,
    _format_fields,
    build_seed_context,
    estimate_history_tokens,
    estimate_tokens,
    normalize_history,
)
from .ai.chat.service import ChatProviderError, send_chat_message
from .ai.prompts import CHAT_SYSTEM_PROMPT

__all__ = [
    "ALLOWED_CHAT_ROLES",
    "CHAT_COMPRESSION_MAX_TOKENS",
    "CHAT_COMPRESSION_THRESHOLD",
    "CHAT_CONTEXT_BUDGET",
    "CHAT_MESSAGE_OVERHEAD",
    "CHAT_RECENT_MESSAGES",
    "CHAT_RESPONSE_RESERVE",
    "CHAT_SEED_BUDGET",
    "CHAT_SYSTEM_PROMPT",
    "CONVERSATION_SUMMARY_PREFIX",
    "MAX_CHAT_MESSAGE_CHARS",
    "MAX_SEED_CHARS",
    "OMITTED_FINDINGS_NOTICE",
    "TOKEN_CHAR_RATIO",
    "ChatProviderError",
    "_append_if_value",
    "_compact",
    "_format_fields",
    "build_seed_context",
    "estimate_history_tokens",
    "estimate_tokens",
    "maybe_compress",
    "normalize_history",
    "send_chat_message",
]
