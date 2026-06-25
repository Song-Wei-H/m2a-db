"""Non-blocking validation helpers for learning datasets."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from worker.feature_builder import FEATURE_COLUMNS


@dataclass(frozen=True)
class DatasetValidationResult:
    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


class DatasetValidator:
    """Validate dataset shape without blocking execution."""

    def validate(self, rows: list[dict[str, Any]]) -> DatasetValidationResult:
        errors: list[str] = []
        warnings: list[str] = []

        seen_keys = Counter(_row_key(row) for row in rows)
        duplicate_count = sum(1 for count in seen_keys.values() if count > 1)
        if duplicate_count:
            warnings.append(f"duplicate row groups detected: {duplicate_count}")

        for index, row in enumerate(rows):
            prefix = f"row[{index}]"
            feature_vector = row.get("feature_vector") or row
            if row.get("target_id") is None:
                errors.append(f"{prefix}: missing target")
            if int(row.get("round_number") or 0) < 0:
                errors.append(f"{prefix}: invalid round")
            if not row.get("selected_tool") and not row.get("tool_name"):
                warnings.append(f"{prefix}: invalid tool")
            if row.get("service") == "":
                warnings.append(f"{prefix}: invalid service")
            if row.get("round_value") is None:
                errors.append(f"{prefix}: missing label")
            if _score_invalid(row.get("round_value")):
                errors.append(f"{prefix}: invalid score")

            missing_features = [column for column in FEATURE_COLUMNS if feature_vector.get(column) is None]
            if missing_features:
                warnings.append(f"{prefix}: missing feature {','.join(missing_features)}")
            if len([column for column in FEATURE_COLUMNS if column in feature_vector]) != len(FEATURE_COLUMNS):
                warnings.append(f"{prefix}: feature dimension mismatch")

        return DatasetValidationResult(valid=not errors, errors=errors, warnings=warnings)


def _row_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        row.get("target_id"),
        row.get("scan_run_id"),
        row.get("round_number"),
        row.get("selected_tool") or row.get("tool_name"),
    )


def _score_invalid(value: Any) -> bool:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return True
    return score < -100 or score > 100
