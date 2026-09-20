#!/usr/bin/env python3
"""
PENTRON - api/schemas.py
Pydantic request/response models. Field allowlists here mirror db.py's own
runtime `allowed` sets (edit_vulnerability/edit_exploit) so a malformed
request is rejected with a clean 422 instead of relying solely on db.py.
"""

from typing import Literal

from pydantic import BaseModel, Field, field_validator

from pentron.chat import MAX_CHAT_MESSAGE_CHARS

MAX_CHAT_HISTORY_MESSAGES = 100


class ScanCreateRequest(BaseModel):
    target: str
    tools: list[str] | Literal["a", "n"] = "a"
    subdomain_discovery_level: int | None = None


class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(max_length=MAX_CHAT_MESSAGE_CHARS)

    @field_validator("content")
    @classmethod
    def validate_content(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Message content cannot be empty")
        return value


class ChatRequest(BaseModel):
    history: list[ChatMessage] = Field(
        default_factory=list, max_length=MAX_CHAT_HISTORY_MESSAGES
    )
    message: str = Field(max_length=MAX_CHAT_MESSAGE_CHARS)

    @field_validator("message")
    @classmethod
    def validate_message(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Chat message cannot be empty")
        return value


class ChatResponse(BaseModel):
    reply: str
    history: list[ChatMessage]


class VulnEditRequest(BaseModel):
    field: Literal["vuln_name", "severity", "port", "service", "description"]
    value: str


class FixEditRequest(BaseModel):
    fix_text: str


class ExploitEditRequest(BaseModel):
    field: Literal["exploit_name", "tool_used", "payload", "result", "notes"]
    value: str


class RiskEditRequest(BaseModel):
    risk: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


class SettingsUpdateRequest(BaseModel):
    provider: Literal["ollama", "openai", "anthropic", "google"] | None = None
    model: str | None = None
    ollama_host: str | None = None
    api_key: str | None = None
    ollama_timeout: int | None = None
    summary_timeout: int | None = None
    scan_delay_seconds: int | None = None
    user_agent: str | None = None
    subdomain_discovery_level: int | None = None
