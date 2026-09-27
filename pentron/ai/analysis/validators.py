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
    try:
        return validate_analysis_response(response), response
    except (ValueError, json.JSONDecodeError, ValidationError) as first_error:
        repaired = provider.send(
            [
                {"role": "system", "content": REPAIR_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Validation error: {first_error}\n\nAnswer:\n{response.text}"
                    ),
                },
            ],
            max_tokens=max_tokens,
            temperature=0.1,
        )
        repaired = _as_response(repaired)
        try:
            return validate_analysis_response(repaired), repaired
        except (ValueError, json.JSONDecodeError, ValidationError) as repair_error:
            raise AnalysisIncompleteError(
                f"AI response remained invalid after repair: {repair_error}",
                response.text,
                tool_calls,
            ) from repair_error
