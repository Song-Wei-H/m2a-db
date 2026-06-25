"""Dataset quality report for future training readiness."""

from __future__ import annotations

from collections import Counter
from typing import Any

from worker.feature_builder import FEATURE_COLUMNS


def build_training_data_report(dataset: list[dict[str, Any]]) -> dict[str, Any]:
    labels = [float(row.get("round_value") or 0.0) for row in dataset]
    distribution = Counter(_label_bucket(value) for value in labels)
    duplicate_groups = Counter(_row_key(row) for row in dataset)
    duplicate_rows = sum(count - 1 for count in duplicate_groups.values() if count > 1)
    total_cells = max(len(dataset) * len(FEATURE_COLUMNS), 1)
    missing_cells = 0
    complete_features = 0
    label_missing = 0

    for row in dataset:
        row_complete = True
        if row.get("round_value") is None:
            label_missing += 1
        for column in FEATURE_COLUMNS:
            missing = row.get(column) is None
            if missing:
                missing_cells += 1
                row_complete = False
        if row_complete:
            complete_features += 1

    return {
        "dataset_size": len(dataset),
        "available_samples": len(dataset),
        "label_distribution": dict(distribution),
        "class_balance": _class_balance(distribution),
        "average_round_value": sum(labels) / len(labels) if labels else 0.0,
        "label_completeness": 1 - (label_missing / len(dataset)) if dataset else 0.0,
        "duplicate_rate": duplicate_rows / len(dataset) if dataset else 0.0,
        "missing_rate": missing_cells / total_cells,
        "missing_feature_rate": missing_cells / total_cells,
        "feature_completeness": complete_features / len(dataset) if dataset else 0.0,
        "tool_distribution": dict(Counter(row.get("selected_tool") or row.get("tool_name") for row in dataset)),
        "service_distribution": dict(Counter(row.get("service") for row in dataset)),
        "round_distribution": dict(Counter(str(row.get("round_number")) for row in dataset)),
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


def _row_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        row.get("target_id"),
        row.get("scan_run_id"),
        row.get("round_number"),
        row.get("selected_tool") or row.get("tool_name"),
    )
