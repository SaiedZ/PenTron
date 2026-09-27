"""Stable high-level API for target analysis."""

import re

from ..providers.factory import get_provider
from .validators import AnalysisIncompleteError as AnalysisIncompleteError
from .workflow import run_analysis_workflow

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def verify_cve_citations(vulnerabilities: list, raw_scan: str) -> list:
    raw_upper = raw_scan.upper()
    for vuln in vulnerabilities:
        text = f"{vuln.get('description', '')} {vuln.get('fix', '')}"
        for cve in CVE_RE.findall(text):
            if (
                cve.upper() not in raw_upper
                and "[UNVERIFIED CVE" not in vuln["description"]
            ):
                vuln["description"] = (
                    vuln["description"]
                    + f" [UNVERIFIED CVE — {cve} not present in scan data]"
                ).strip()
    return vulnerabilities


def analyse_target(
    target: str,
    raw_scan: str,
    provider=None,
    on_progress=None,
    allowed_subdomains: frozenset = frozenset(),
) -> dict:
    provider = provider or get_provider()
    parsed, tool_call_records = run_analysis_workflow(
        target, raw_scan, provider, on_progress, allowed_subdomains
    )

    vulnerabilities = [
        {
            "vuln_name": item.name,
            "severity": item.severity,
            "port": item.port,
            "service": item.service,
            "description": f"{item.description} Evidence: {item.evidence}",
            "fix": item.fix,
        }
        for item in parsed.vulnerabilities
    ]
    verify_cve_citations(vulnerabilities, raw_scan)
    return {
        "full_response": parsed.analysis_markdown,
        "vulnerabilities": vulnerabilities,
        "exploit_suggestions": [x.model_dump() for x in parsed.exploit_suggestions],
        "tool_calls": tool_call_records,
        "risk_level": parsed.risk_level,
        "summary": parsed.short_summary,
        "raw_scan": raw_scan,
    }
