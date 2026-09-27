"""Repeatable evaluation of sanitized reference scans and engine outputs."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class QualityScore:
    true_positives: int
    false_positives: int
    false_negatives: int
    severity_matches: int
    provenance_matches: int

    @property
    def precision(self) -> float:
        total = self.true_positives + self.false_positives
        return self.true_positives / total if total else 1.0

    @property
    def recall(self) -> float:
        total = self.true_positives + self.false_negatives
        return self.true_positives / total if total else 1.0


def load_corpus(path: Path) -> dict[str, dict[str, Any]]:
    cases = {}
    for fixture in sorted(path.glob("*.json")):
        case = json.loads(fixture.read_text(encoding="utf-8"))
        case_id = case["id"]
        if case_id in cases:
            raise ValueError(f"duplicate corpus case: {case_id}")
        cases[case_id] = case
    return cases


def _key(finding: dict) -> str:
    return finding.get("id", finding.get("name", finding.get("vuln_name", "")))


def score_case(case: dict, result: dict) -> QualityScore:
    expected = {_key(item): item for item in case.get("expected_findings", [])}
    actual = {_key(item): item for item in result.get("findings", [])}
    alternatives = {
        alternative: expected_id
        for expected_id, item in expected.items()
        for alternative in item.get("acceptable_alternatives", [])
    }
    normalized_actual = {
        alternatives.get(actual_id, actual_id): item
        for actual_id, item in actual.items()
    }
    matched = set(expected) & set(normalized_actual)
    unexpected = set(normalized_actual) - set(expected)
    severity_matches = sum(
        normalized_actual[item].get("severity", "").lower()
        == expected[item].get("severity", "").lower()
        for item in matched
    )
    provenance_matches = sum(
        set(expected[item].get("evidence_refs", []))
        <= set(normalized_actual[item].get("evidence_refs", []))
        for item in matched
    )
    return QualityScore(
        true_positives=len(matched),
        false_positives=len(unexpected),
        false_negatives=len(set(expected) - matched),
        severity_matches=severity_matches,
        provenance_matches=provenance_matches,
    )


def evaluate(corpus: dict[str, dict], run: dict) -> dict:
    scores = {}
    totals = QualityScore(0, 0, 0, 0, 0)
    for case_id, case in corpus.items():
        score = score_case(case, run.get("cases", {}).get(case_id, {}))
        scores[case_id] = asdict(score) | {
            "precision": score.precision,
            "recall": score.recall,
        }
        totals = QualityScore(
            *(
                left + right
                for left, right in zip(
                    asdict(totals).values(), asdict(score).values(), strict=True
                )
            )
        )
    metadata = run.get("metadata", {})
    return {
        "schema_version": 1,
        "metadata": {
            key: metadata.get(key, "missing")
            for key in ("provider", "model", "prompt", "policy", "code_version")
        },
        "quality": asdict(totals)
        | {"precision": totals.precision, "recall": totals.recall},
        "performance": {
            key: metadata.get(key, "missing")
            for key in ("input_tokens", "output_tokens", "cost", "duration_ms")
        },
        "safety": {"blocked_tool_calls": metadata.get("blocked_tool_calls", "missing")},
        "cases": scores,
    }


def compare_reports(baseline: dict, candidate: dict) -> dict:
    quality_keys = (
        "true_positives",
        "false_positives",
        "false_negatives",
        "severity_matches",
        "provenance_matches",
        "precision",
        "recall",
    )
    return {
        "schema_version": 1,
        "baseline": baseline.get("metadata", {}),
        "candidate": candidate.get("metadata", {}),
        "quality_delta": {
            key: candidate["quality"][key] - baseline["quality"][key]
            for key in quality_keys
        },
        "performance": {
            "baseline": baseline.get("performance", {}),
            "candidate": candidate.get("performance", {}),
        },
        "safety": {
            "baseline": baseline.get("safety", {}),
            "candidate": candidate.get("safety", {}),
        },
        "case_differences": {
            case_id: {
                "baseline": baseline.get("cases", {}).get(case_id),
                "candidate": candidate.get("cases", {}).get(case_id),
            }
            for case_id in sorted(
                set(baseline.get("cases", {})) | set(candidate.get("cases", {}))
            )
            if baseline.get("cases", {}).get(case_id)
            != candidate.get("cases", {}).get(case_id)
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    evaluate_parser = subparsers.add_parser("evaluate")
    evaluate_parser.add_argument("corpus", type=Path)
    evaluate_parser.add_argument("run", type=Path)
    compare_parser = subparsers.add_parser("compare")
    compare_parser.add_argument("baseline", type=Path)
    compare_parser.add_argument("candidate", type=Path)
    args = parser.parse_args()
    if args.command == "evaluate":
        output = evaluate(load_corpus(args.corpus), json.loads(args.run.read_text()))
    else:
        output = compare_reports(
            json.loads(args.baseline.read_text()),
            json.loads(args.candidate.read_text()),
        )
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
