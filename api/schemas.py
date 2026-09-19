#!/usr/bin/env python3
"""
METATRON - api/schemas.py
Pydantic request/response models. Field allowlists here mirror db.py's own
runtime `allowed` sets (edit_vulnerability/edit_exploit) so a malformed
request is rejected with a clean 422 instead of relying solely on db.py.
"""

from typing import List, Literal, Optional, Union

from pydantic import BaseModel


class ScanCreateRequest(BaseModel):
    target: str
    tools: Union[List[str], Literal["a", "n"]] = "a"
    subdomain_discovery_level: Optional[int] = None


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
    provider: Optional[Literal["ollama", "openai", "anthropic", "google"]] = None
    model: Optional[str] = None
    ollama_host: Optional[str] = None
    api_key: Optional[str] = None
    ollama_timeout: Optional[int] = None
    summary_timeout: Optional[int] = None
    scan_delay_seconds: Optional[int] = None
    user_agent: Optional[str] = None
    subdomain_discovery_level: Optional[int] = None
