import json

import pytest

from api.routers.pages import render_safe_markdown
from pentron.llm import AnalysisIncompleteError, analyse_target
from pentron.providers import ProviderResponse


def valid_result(**overrides):
    data = {
        "risk_level": "LOW",
        "short_summary": "No material weakness was confirmed.",
        "analysis_markdown": "## Assessment\n\nNo confirmed findings.",
        "vulnerabilities": [],
        "exploit_suggestions": [],
    }
    data.update(overrides)
    return json.dumps(data)


class FakeProvider:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def send(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        return next(self.responses)


def test_valid_json_is_structured():
    provider = FakeProvider([ProviderResponse(valid_result(), "stop")])

    result = analyse_target("example.test", "short evidence", provider=provider)

    assert result["risk_level"] == "LOW"
    assert result["summary"].startswith("No material")
    assert result["vulnerabilities"] == []
    assert len(provider.calls) == 1


def test_invalid_json_is_repaired_once():
    provider = FakeProvider(
        [ProviderResponse("not json", "stop"), ProviderResponse(valid_result(), "stop")]
    )

    result = analyse_target("example.test", "short evidence", provider=provider)

    assert result["risk_level"] == "LOW"
    assert len(provider.calls) == 2


def test_truncated_then_invalid_becomes_partial():
    provider = FakeProvider(
        [
            ProviderResponse('{"risk_level":', "length", True),
            ProviderResponse("still invalid", "stop"),
        ]
    )

    with pytest.raises(AnalysisIncompleteError) as exc_info:
        analyse_target("example.test", "short evidence", provider=provider)

    assert "remained invalid" in str(exc_info.value)
    assert len(provider.calls) == 2


def test_markdown_renderer_disables_raw_html_and_unsafe_links():
    rendered = str(
        render_safe_markdown(
            "## Safe\n<script>alert(1)</script>\n[x](javascript:alert(1))"
        )
    )

    assert "<h2>Safe</h2>" in rendered
    assert "<script>" not in rendered
    assert 'href="javascript:' not in rendered
