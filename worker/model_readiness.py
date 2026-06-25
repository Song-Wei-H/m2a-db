"""Offline model training readiness checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from worker.training_data_report import build_training_data_report


MIN_TRAINING_SAMPLES = 500


@dataclass(frozen=True)
class ModelReadinessResult:
    ready: bool
    reasons: list[str]
    report: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "reasons": list(self.reasons),
            "report": self.report,
        }


def check_model_readiness(dataset: list[dict[str, Any]]) -> ModelReadinessResult:
    report = build_training_data_report(dataset)
    reasons: list[str] = []

    if report["dataset_size"] < MIN_TRAINING_SAMPLES:
        reasons.append(f"dataset_size below {MIN_TRAINING_SAMPLES}")
    if len(report["label_distribution"]) < 2:
        reasons.append("label distribution has fewer than two classes")
    if report["feature_completeness"] < 0.8:
        reasons.append("feature completeness below 0.8")
    if report["duplicate_rate"] > 0.1:
        reasons.append("duplicate rate above 0.1")
    if report["missing_rate"] > 0.2:
        reasons.append("missing rate above 0.2")

    return ModelReadinessResult(ready=not reasons, reasons=reasons, report=report)
