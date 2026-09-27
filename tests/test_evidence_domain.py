import pytest
from pydantic import ValidationError

from pentron.ai.analysis.service import _complete_raw_scan
from pentron.ai.evidence import (
    EvidenceDomain,
    Fact,
    Finding,
    Observation,
    RawSourceReference,
    conflicts_from_observations,
    facts_from_observations,
    observations_from_raw,
)

RAW = """==================================================
[ NMAP OUTPUT ]
==================================================
80/tcp open http Apache
80/tcp open http Apache
443/tcp open https
"""


def test_observations_preserve_raw_provenance_and_deduplicate():
    observations = observations_from_raw(RAW)

    assert [item.value for item in observations] == [
        "80/tcp open http Apache",
        "443/tcp open https",
    ]
    assert observations[0].raw_source.start_line == 4
    assert observations[0].tool == "nmap"


def test_facts_have_confidence_and_reference_observations():
    observations = observations_from_raw(RAW)
    facts = facts_from_observations(observations)

    assert facts[0].confidence == 1.0
    assert facts[0].observation_ids == [observations[0].id]


def test_broken_fact_reference_is_rejected():
    with pytest.raises(ValidationError, match="broken observations"):
        EvidenceDomain(
            observations=[],
            facts=[
                Fact(
                    id="fact-1",
                    statement="port open",
                    observation_ids=["missing"],
                    confidence=0.8,
                )
            ],
        )


def test_finding_keeps_raw_evidence_and_rejects_broken_fact():
    observation = Observation(
        id="obs-1",
        tool="nmap",
        value="80/tcp open",
        raw_source=RawSourceReference(start_line=1, end_line=1, excerpt="80/tcp open"),
    )
    finding = Finding(
        id="finding-1",
        title="HTTP exposed",
        severity="low",
        description="HTTP is reachable",
        fact_ids=["missing"],
        evidence=[observation.raw_source],
        remediation="Use TLS",
    )
    with pytest.raises(ValidationError, match="broken facts"):
        EvidenceDomain(observations=[observation], facts=[], findings=[finding])


def test_hypotheses_are_not_facts():
    schema = EvidenceDomain.model_json_schema()
    assert "hypotheses" in schema["properties"]
    assert "facts" in schema["properties"]


def test_conflicting_observations_are_reported_not_silently_resolved():
    observations = observations_from_raw("Header: enabled\nHeader: disabled")
    assert "conflicting values" in conflicts_from_observations(observations)[0]


def test_stale_raw_reference_is_rejected():
    observation = Observation(
        id="obs-1",
        tool="nmap",
        value="80/tcp open",
        raw_source=RawSourceReference(start_line=1, end_line=1, excerpt="80/tcp open"),
    )
    domain = EvidenceDomain(
        observations=[observation], facts=facts_from_observations([observation])
    )
    with pytest.raises(ValueError, match="excerpt does not match"):
        domain.validate_raw_source("443/tcp open")


def test_executed_ai_tool_output_becomes_raw_evidence():
    completed = _complete_raw_scan(
        "initial",
        [
            {
                "command": "nmap -sV example.test",
                "result": "22/tcp open ssh",
                "blocked": False,
            },
            {"command": "blocked", "result": "secret", "blocked": True},
        ],
    )
    assert "22/tcp open ssh" in completed
    assert "secret" not in completed
