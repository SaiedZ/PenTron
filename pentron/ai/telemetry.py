"""Privacy-preserving metrics for one AI analysis run."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from time import perf_counter
from typing import Any
from uuid import uuid4

from .chat.context import estimate_message_tokens, estimate_tokens
from .providers.base import ProviderResponse


@dataclass
class ProviderRequestMetric:
    purpose: str
    input_tokens: int
    output_tokens: int
    usage_source: str
    duration_ms: int
    outcome: str


@dataclass
class CompressionMetric:
    policy: str
    model: str
    input_tokens: int
    output_tokens: int


@dataclass
class AnalysisTelemetry:
    """Aggregated, content-free telemetry attached to an analysis result."""

    run_id: str
    provider: str
    model: str
    started_at: str
    duration_ms: int = 0
    rounds: int = 0
    proposed_tool_calls: int = 0
    executed_tool_calls: int = 0
    blocked_tool_calls: int = 0
    first_pass_valid: bool | None = None
    repair_attempts: int = 0
    validation_outcome: str = "unknown"
    validation_failure_reason: str | None = None
    requests: list[ProviderRequestMetric] = field(default_factory=list)
    compressions: list[CompressionMetric] = field(default_factory=list)

    @property
    def input_tokens(self) -> int:
        return sum(item.input_tokens for item in self.requests)

    @property
    def output_tokens(self) -> int:
        return sum(item.output_tokens for item in self.requests)

    @property
    def token_usage_source(self) -> str:
        sources = {item.usage_source for item in self.requests}
        if not sources:
            return "unavailable"
        return sources.pop() if len(sources) == 1 else "mixed"

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.update(
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
            token_usage_source=self.token_usage_source,
        )
        return data


class InstrumentedProvider:
    """Transparent provider proxy recording request-level usage and latency."""

    def __init__(self, provider, telemetry: AnalysisTelemetry):
        self._provider = provider
        self.telemetry = telemetry
        self.purpose = "analysis"

    def __getattr__(self, name):
        return getattr(self._provider, name)

    def send(self, messages: list, **kwargs) -> ProviderResponse:
        started = perf_counter()
        response = self._provider.send(messages, **kwargs)
        duration_ms = round((perf_counter() - started) * 1000)
        if not isinstance(response, ProviderResponse):
            response = ProviderResponse(str(response))
        input_tokens = response.input_tokens
        output_tokens = response.output_tokens
        source = response.usage_source
        input_estimated = input_tokens is None
        output_estimated = output_tokens is None
        if input_tokens is None:
            input_tokens = estimate_message_tokens(messages)
        if output_tokens is None:
            output_tokens = estimate_tokens(response.text)
        if input_estimated or output_estimated:
            source = (
                "estimated"
                if input_estimated
                and output_estimated
                and response.usage_source == "unavailable"
                else "mixed"
            )
        self.telemetry.requests.append(
            ProviderRequestMetric(
                purpose=self.purpose,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                usage_source=source,
                duration_ms=duration_ms,
                outcome=response.finish_reason,
            )
        )
        return response


def new_analysis_telemetry(provider, started_at: str) -> AnalysisTelemetry:
    return AnalysisTelemetry(
        run_id=str(uuid4()),
        provider=str(getattr(provider, "provider_name", "unknown")),
        model=str(getattr(provider, "model", "unknown")),
        started_at=started_at,
    )
