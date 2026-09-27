"""Stable high-level API for target analysis."""

import re

from pydantic import ValidationError

from ..evidence import (
    EvidenceDomain,
    Finding,
    conflicts_from_observations,
    evidence_for_text,
    facts_from_observations,
    observations_from_raw,
)
from ..providers.factory import get_provider
from .validators import AnalysisIncompleteError as AnalysisIncompleteError
from .workflow import run_analysis_workflow

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _complete_raw_scan(raw_scan: str, tool_calls: list[dict]) -> str:
    sections = [raw_scan.rstrip()]
    for index, call in enumerate(tool_calls, 1):
        if call.get("blocked") or not call.get("result", "").strip():
            continue
        sections.append(
            "\n".join(
                [
                    "=" * 50,
                    f"[ AI TOOL {index}: {call.get('command', 'unknown')} OUTPUT ]",
                    "=" * 50,
                    call["result"].strip(),
                ]
            )
        )
    return "\n".join(section for section in sections if section)


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
    raw_scan = _complete_raw_scan(raw_scan, tool_call_records)

    observations = observations_from_raw(raw_scan)
    facts = facts_from_observations(observations)
    fact_by_observation = {
        fact.observation_ids[0]: fact for fact in facts if fact.observation_ids
    }
    findings = []
    for index, item in enumerate(parsed.vulnerabilities, 1):
        observation = evidence_for_text(item.evidence, observations)
        if observation is None:
            raise AnalysisIncompleteError(
                f"finding {index} evidence does not reference raw tool output"
            )
        fact = fact_by_observation[observation.id]
        findings.append(
            Finding(
                id=f"finding-{index}",
                title=item.name,
                severity=item.severity,
                description=item.description,
                fact_ids=[fact.id],
                hypothesis_ids=item.hypothesis_ids,
                evidence=[observation.raw_source],
                remediation=item.fix,
                port=item.port,
                service=item.service,
            )
        )
    try:
        domain = EvidenceDomain(
            observations=observations,
            facts=facts,
            hypotheses=parsed.hypotheses,
            findings=findings,
            conflicts=conflicts_from_observations(observations),
        )
        domain.validate_raw_source(raw_scan)
    except (ValidationError, ValueError) as exc:
        raise AnalysisIncompleteError(f"invalid evidence graph: {exc}") from exc

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
        "evidence_domain": domain.model_dump(mode="json"),
    }
