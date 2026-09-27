"""Evidence-backed analysis domain primitives and deterministic extraction."""

import re
from hashlib import sha256
from typing import Literal

from pydantic import BaseModel, Field, model_validator


def _stable_id(prefix: str, value: str) -> str:
    return f"{prefix}-{sha256(value.encode()).hexdigest()[:12]}"


class RawSourceReference(BaseModel):
    source_id: str = "raw_scan"
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    excerpt: str = Field(min_length=1)

    @model_validator(mode="after")
    def valid_range(self):
        if self.end_line < self.start_line:
            raise ValueError("evidence end_line precedes start_line")
        return self


class Observation(BaseModel):
    id: str
    tool: str
    value: str = Field(min_length=1)
    raw_source: RawSourceReference


class Fact(BaseModel):
    id: str
    statement: str = Field(min_length=1)
    observation_ids: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0, le=1)


class Hypothesis(BaseModel):
    id: str
    statement: str = Field(min_length=1)
    evidence_observation_ids: list[str] = []
    status: Literal["unverified", "confirmed", "rejected"] = "unverified"
    validation: str = ""


class Finding(BaseModel):
    id: str
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    description: str
    fact_ids: list[str] = Field(min_length=1)
    hypothesis_ids: list[str] = []
    evidence: list[RawSourceReference] = Field(min_length=1)
    remediation: str
    port: str = ""
    service: str = ""


class EvidenceDomain(BaseModel):
    schema_version: int = 1
    observations: list[Observation]
    facts: list[Fact]
    hypotheses: list[Hypothesis] = []
    findings: list[Finding] = []
    conflicts: list[str] = []

    @model_validator(mode="after")
    def references_exist(self):
        observation_ids = {item.id for item in self.observations}
        fact_ids = {item.id for item in self.facts}
        hypothesis_ids = {item.id for item in self.hypotheses}
        all_ids = [*observation_ids, *fact_ids, *hypothesis_ids]
        if len(all_ids) != len(self.observations) + len(self.facts) + len(
            self.hypotheses
        ):
            raise ValueError("domain IDs must be unique")
        for fact in self.facts:
            missing = set(fact.observation_ids) - observation_ids
            if missing:
                raise ValueError(f"fact {fact.id} has broken observations: {missing}")
        for hypothesis in self.hypotheses:
            missing = set(hypothesis.evidence_observation_ids) - observation_ids
            if missing:
                raise ValueError(
                    f"hypothesis {hypothesis.id} has broken observations: {missing}"
                )
        for finding in self.findings:
            if missing := set(finding.fact_ids) - fact_ids:
                raise ValueError(f"finding {finding.id} has broken facts: {missing}")
            if missing := set(finding.hypothesis_ids) - hypothesis_ids:
                raise ValueError(
                    f"finding {finding.id} has broken hypotheses: {missing}"
                )
        return self

    def validate_raw_source(self, raw_scan: str) -> None:
        """Reject stale or forged line references before persistence."""
        lines = raw_scan.splitlines()
        for observation in self.observations:
            reference = observation.raw_source
            if reference.source_id != "raw_scan" or reference.end_line > len(lines):
                raise ValueError(f"observation {observation.id} has a broken raw ref")
            excerpt = "\n".join(lines[reference.start_line - 1 : reference.end_line])
            if excerpt.strip() != reference.excerpt.strip():
                raise ValueError(f"observation {observation.id} excerpt does not match")
        observation_refs = {
            observation.raw_source.model_dump_json()
            for observation in self.observations
        }
        for finding in self.findings:
            for reference in finding.evidence:
                if reference.model_dump_json() not in observation_refs:
                    raise ValueError(f"finding {finding.id} has a broken evidence ref")


_HEADER = re.compile(r"^\[ (.+) OUTPUT \]$")
_NOISE = re.compile(r"^(?:=+|\s*)$")


def observations_from_raw(raw_scan: str) -> list[Observation]:
    """Turn non-empty tool output lines into stable, line-addressable observations."""
    observations = []
    tool = "unknown"
    seen = set()
    for line_number, line in enumerate(raw_scan.splitlines(), 1):
        value = line.strip()
        if match := _HEADER.match(value):
            tool = match.group(1).lower()
            continue
        if _NOISE.match(value):
            continue
        key = (tool, value.casefold())
        if key in seen:
            continue
        seen.add(key)
        observations.append(
            Observation(
                id=_stable_id("obs", f"{tool}:{value.casefold()}"),
                tool=tool,
                value=value,
                raw_source=RawSourceReference(
                    start_line=line_number, end_line=line_number, excerpt=value
                ),
            )
        )
    return observations


def facts_from_observations(observations: list[Observation]) -> list[Fact]:
    """Promote direct observations to facts without introducing inference."""
    return [
        Fact(
            id=_stable_id("fact", observation.id),
            statement=observation.value,
            observation_ids=[observation.id],
            confidence=1.0,
        )
        for observation in observations
    ]


def conflicts_from_observations(observations: list[Observation]) -> list[str]:
    """Report contradictory key/value observations without resolving them."""
    values_by_key: dict[tuple[str, str], set[str]] = {}
    for observation in observations:
        if ":" not in observation.value:
            continue
        key, value = observation.value.split(":", 1)
        values_by_key.setdefault((observation.tool, key.strip().casefold()), set()).add(
            value.strip()
        )
    return [
        f"{tool}:{key} has conflicting values: {', '.join(sorted(values))}"
        for (tool, key), values in values_by_key.items()
        if len(values) > 1
    ]


def evidence_for_text(text: str, observations: list[Observation]) -> Observation | None:
    normalized = " ".join(text.casefold().split())
    if not normalized:
        return None
    for observation in observations:
        candidate = " ".join(observation.value.casefold().split())
        if normalized in candidate or candidate in normalized:
            return observation
    return None
