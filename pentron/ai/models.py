"""Validated data models returned by the analysis engine."""

from typing import Literal

from pydantic import BaseModel, Field


class VulnerabilityResult(BaseModel):
    name: str
    severity: Literal["critical", "high", "medium", "low"]
    port: str = ""
    service: str = ""
    evidence: str
    description: str
    fix: str


class ExploitSuggestion(BaseModel):
    name: str
    rationale: str
    tool: str = ""
    safe_validation: str = ""


class AnalysisResult(BaseModel):
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    short_summary: str = Field(min_length=1, max_length=1200)
    analysis_markdown: str = Field(min_length=1)
    vulnerabilities: list[VulnerabilityResult]
    exploit_suggestions: list[ExploitSuggestion]
