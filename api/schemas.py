#!/usr/bin/env python3
"""
PENTRON - api/schemas.py
Pydantic request/response models. Field allowlists here mirror db.py's own
runtime `allowed` sets (edit_vulnerability/edit_exploit) so a malformed
request is rejected with a clean 422 instead of relying solely on db.py.
"""

from typing import Literal

from pydantic import BaseModel


class ScanCreateRequest(BaseModel):
    target: str
    tools: list[str] | Literal["a", "n"] = "a"
    subdomain_discovery_level: int | None = None


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
