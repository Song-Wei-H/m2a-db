"""Dataset quality report for future training readiness."""

from __future__ import annotations

from collections import Counter
from typing import Any

from worker.feature_builder import FEATURE_COLUMNS


def build_training_data_report(dataset: list[dict[str, Any]]) -> dict[str, Any]:
    labels = [float(row.get("round_value") or 0.0) for row in dataset]
    distribution = Counter(_label_bucket(value) for value in labels)
    total_cells = max(len(dataset) * len(FEATURE_COLUMNS), 1)
    missing_cells = 0
    complete_features = 0

    for row in dataset:
        row_complete = True
        for column in FEATURE_COLUMNS:
            missing = row.get(column) is None
            if missing:
                missing_cells += 1
                row_complete = False
        if row_complete:
            complete_features += 1

    return {
        "available_samples": len(dataset),
        "label_distribution": dict(distribution),
        "class_balance": _class_balance(distribution),
        "average_round_value": sum(labels) / len(labels) if labels else 0.0,
        "missing_feature_rate": missing_cells / total_cells,
        "feature_completeness": complete_features / len(dataset) if dataset else 0.0,
        "suitable_for_training": len(dataset) >= 100 and len(distribution) >= 2,
    }


def _label_bucket(value: float) -> str:
    if value > 0:
        return "positive"
    if value < 0:
        return "negative"
    return "zero"


def _class_balance(distribution: Counter) -> dict[str, float]:
    total = sum(distribution.values())
    if total == 0:
        return {}
    return {label: count / total for label, count in sorted(distribution.items())}
