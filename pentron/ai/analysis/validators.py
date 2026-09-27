"""Validation and one-shot repair of structured analysis responses."""

import json
import re

from pydantic import ValidationError

from ..models import AnalysisResult
from ..prompts import REPAIR_SYSTEM_PROMPT
from ..providers.base import ProviderResponse


class AnalysisIncompleteError(RuntimeError):
    def __init__(self, message: str, raw_response: str = "", tool_calls=None):
        super().__init__(message)
        self.raw_response = raw_response
        self.tool_calls = tool_calls or []
        self.telemetry = None


def _failure_category(error: Exception) -> str:
    if isinstance(error, json.JSONDecodeError):
        return "invalid_json"
    if isinstance(error, ValidationError):
        return "schema_validation"
    message = str(error).lower()
    if "stopped early" in message:
        return "truncated"
    return "invalid_response"


def _as_response(response) -> ProviderResponse:
    if isinstance(response, ProviderResponse):
        return response
    return ProviderResponse(str(response))


def validate_analysis_response(response: ProviderResponse) -> AnalysisResult:
    if response.truncated:
        raise ValueError(f"provider stopped early ({response.finish_reason})")
    text = response.text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.I)
    return AnalysisResult.model_validate(json.loads(text))


def validate_or_repair_analysis(
    provider,
    response,
    *,
    max_tokens: int,
    tool_calls: list[dict] | None = None,
) -> tuple[AnalysisResult, ProviderResponse]:
    response = _as_response(response)
    telemetry = getattr(provider, "telemetry", None)
    try:
        parsed = validate_analysis_response(response)
        if telemetry is not None:
            telemetry.first_pass_valid = True
            telemetry.validation_outcome = "valid"
        return parsed, response
    except (ValueError, json.JSONDecodeError, ValidationError) as first_error:
        if telemetry is not None:
            telemetry.first_pass_valid = False
            telemetry.repair_attempts += 1
            telemetry.validation_failure_reason = _failure_category(first_error)
        previous_purpose = getattr(provider, "purpose", None)
        if previous_purpose is not None:
            provider.purpose = "repair"
        try:
            repaired = provider.send(
                [
                    {"role": "system", "content": REPAIR_SYSTEM_PROMPT},
                    {
                        "role": "user",
                        "content": (
                            f"Validation error: {first_error}\n\nAnswer:\n"
                            f"{response.text}"
                        ),
                    },
                ],
                max_tokens=max_tokens,
                temperature=0.1,
            )
        finally:
            if previous_purpose is not None:
                provider.purpose = previous_purpose
        repaired = _as_response(repaired)
        try:
            parsed = validate_analysis_response(repaired)
            if telemetry is not None:
                telemetry.validation_outcome = "repaired"
            return parsed, repaired
        except (ValueError, json.JSONDecodeError, ValidationError) as repair_error:
            if telemetry is not None:
                telemetry.validation_outcome = "failed"
                telemetry.validation_failure_reason = _failure_category(repair_error)
            raise AnalysisIncompleteError(
                f"AI response remained invalid after repair: {repair_error}",
                response.text,
                tool_calls,
            ) from repair_error
