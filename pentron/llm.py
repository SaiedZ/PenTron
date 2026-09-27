"""Temporary compatibility facade for the modular :mod:`pentron.ai` engine."""

import os
import re

from .ai.analysis.service import (
    AnalysisIncompleteError,
    analyse_target,
    verify_cve_citations,
)
from .ai.analysis.tool_dispatch import (
    extract_tool_calls,
    run_tool_calls,
    summarize_tool_output,
)
from .ai.analysis.workflow import MAX_TOKENS, MAX_TOOL_LOOPS, SUMMARY_THRESHOLD
from .ai.models import AnalysisResult, ExploitSuggestion, VulnerabilityResult
from .ai.prompts import FINAL_PROMPT, SYSTEM_PROMPT
from .providers import OllamaProvider

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "localhost:11434")
MODEL_NAME = "huihui_ai/qwen3.5-abliterated:9b"
OLLAMA_TIMEOUT = 600


def ask_ollama(messages: list) -> str:
    """Thin wrapper retained for direct and test use."""
    print(f"\n[*] Sending to {MODEL_NAME}...")
    return (
        OllamaProvider(MODEL_NAME, timeout=OLLAMA_TIMEOUT)
        .send(messages, max_tokens=MAX_TOKENS)
        .text
    )


def _clean(line: str) -> str:
    return re.sub(r"\*+", "", line).strip()


def parse_vulnerabilities(response: str) -> list:
    """Parse the legacy line-based finding format."""
    vulns = []
    lines = response.splitlines()
    for index, raw_line in enumerate(lines):
        line = _clean(raw_line)
        if not line.startswith("VULN:"):
            continue
        vuln = {
            "vuln_name": "",
            "severity": "medium",
            "port": "",
            "service": "",
            "description": "",
            "fix": "",
        }
        for part in line.split("|"):
            part = part.strip()
            for prefix, key in (
                ("VULN:", "vuln_name"),
                ("SEVERITY:", "severity"),
                ("PORT:", "port"),
                ("SERVICE:", "service"),
            ):
                if part.startswith(prefix):
                    value = part.removeprefix(prefix).strip()
                    vuln[key] = value.lower() if key == "severity" else value
        for following in lines[index + 1 : index + 6]:
            following = _clean(following)
            if following.startswith(("VULN:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                break
            if following.startswith("DESC:"):
                vuln["description"] = following.removeprefix("DESC:").strip()
            elif following.startswith("FIX:"):
                vuln["fix"] = following.removeprefix("FIX:").strip()
        if vuln["vuln_name"]:
            vulns.append(vuln)
    return vulns


def parse_risk_level(response: str) -> str:
    match = re.search(
        r"RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)", response, re.IGNORECASE
    )
    return match.group(1).upper() if match else "UNKNOWN"


def parse_summary(response: str) -> str:
    match = re.search(r"SUMMARY:\s*(.+)", response, re.IGNORECASE)
    return match.group(1).strip() if match else ""


__all__ = [
    "AnalysisIncompleteError",
    "AnalysisResult",
    "ExploitSuggestion",
    "FINAL_PROMPT",
    "MAX_TOOL_LOOPS",
    "SUMMARY_THRESHOLD",
    "SYSTEM_PROMPT",
    "VulnerabilityResult",
    "analyse_target",
    "ask_ollama",
    "extract_tool_calls",
    "parse_risk_level",
    "parse_summary",
    "parse_vulnerabilities",
    "run_tool_calls",
    "summarize_tool_output",
    "verify_cve_citations",
]
