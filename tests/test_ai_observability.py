import json
from pathlib import Path

from pentron.ai.analysis.validators import validate_or_repair_analysis
from pentron.ai.evaluation import compare_reports, evaluate, load_corpus, score_case
from pentron.ai.providers import ProviderResponse
from pentron.ai.telemetry import InstrumentedProvider, new_analysis_telemetry


class FakeProvider:
    provider_name = "fake"
    model = "runtime-model-id"
    supports_native_tools = False

    def __init__(self, response):
        self.response = response

    def send(self, messages, **kwargs):
        return self.response


class SequenceProvider(FakeProvider):
    def __init__(self, responses):
        self.responses = list(responses)

    def send(self, messages, **kwargs):
        return self.responses.pop(0)


def test_instrumentation_uses_reported_usage_without_storing_content():
    response = ProviderResponse(
        "sensitive output", input_tokens=12, output_tokens=3, usage_source="provider"
    )
    telemetry = new_analysis_telemetry(FakeProvider(response), "2026-01-01T00:00:00Z")
    provider = InstrumentedProvider(FakeProvider(response), telemetry)

    provider.send([{"role": "user", "content": "sensitive prompt"}])

    data = telemetry.as_dict()
    assert data["provider"] == "fake"
    assert data["model"] == "runtime-model-id"
    assert data["input_tokens"] == 12
    assert data["output_tokens"] == 3
    assert data["token_usage_source"] == "provider"
    assert "sensitive prompt" not in json.dumps(data)
    assert "sensitive output" not in json.dumps(data)


def test_instrumentation_marks_missing_provider_usage_as_estimated():
    response = ProviderResponse("abcd")
    telemetry = new_analysis_telemetry(FakeProvider(response), "now")

    InstrumentedProvider(FakeProvider(response), telemetry).send(
        [{"role": "user", "content": "abcdefgh"}]
    )

    assert telemetry.input_tokens > 0
    assert telemetry.output_tokens == 1
    assert telemetry.token_usage_source == "estimated"


def test_validation_records_first_pass_failure_and_repair():
    valid = json.dumps(
        {
            "analysis_markdown": "No supported findings.",
            "short_summary": "No findings.",
            "risk_level": "LOW",
            "vulnerabilities": [],
            "exploit_suggestions": [],
            "hypotheses": [],
        }
    )
    raw_provider = SequenceProvider([ProviderResponse(valid)])
    telemetry = new_analysis_telemetry(raw_provider, "now")
    provider = InstrumentedProvider(raw_provider, telemetry)

    validate_or_repair_analysis(provider, ProviderResponse("not json"), max_tokens=100)

    assert telemetry.first_pass_valid is False
    assert telemetry.repair_attempts == 1
    assert telemetry.validation_outcome == "repaired"
    assert telemetry.validation_failure_reason == "invalid_json"
    assert telemetry.requests[0].purpose == "repair"


def test_reference_corpus_is_versioned_and_sanitized():
    corpus = load_corpus(Path("tests/fixtures/evaluation"))

    assert corpus
    assert all(case["version"] >= 1 for case in corpus.values())
    assert all("secret" not in case["scan"].lower() for case in corpus.values())


def test_evaluator_scores_alternatives_severity_and_provenance():
    case = {
        "expected_findings": [
            {
                "id": "missing-hsts",
                "severity": "medium",
                "evidence_refs": ["headers"],
                "acceptable_alternatives": ["hsts-absent"],
            }
        ]
    }
    score = score_case(
        case,
        {
            "findings": [
                {
                    "id": "hsts-absent",
                    "severity": "medium",
                    "evidence_refs": ["headers"],
                }
            ]
        },
    )

    assert score.true_positives == 1
    assert score.severity_matches == 1
    assert score.provenance_matches == 1


def test_intentionally_absent_finding_is_a_false_positive_when_returned():
    score = score_case(
        {"expected_findings": [], "intentionally_absent": ["sql-injection"]},
        {"findings": [{"id": "sql-injection", "severity": "high"}]},
    )

    assert score.false_positives == 1


def test_comparison_exposes_missing_cost_and_per_case_changes():
    corpus = {"case-1": {"expected_findings": [{"id": "finding", "severity": "high"}]}}
    baseline = evaluate(corpus, {"metadata": {}, "cases": {}})
    candidate = evaluate(
        corpus,
        {
            "metadata": {"provider": "ollama", "model": "model"},
            "cases": {"case-1": {"findings": [{"id": "finding", "severity": "high"}]}},
        },
    )
    comparison = compare_reports(baseline, candidate)

    assert candidate["performance"]["cost"] == "missing"
    assert comparison["quality_delta"]["true_positives"] == 1
    assert "case-1" in comparison["case_differences"]
