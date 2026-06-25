"""Dataset export helpers for future tree-based models."""

from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from worker.feature_builder import FEATURE_COLUMNS


async def build_dataset(session: AsyncSession) -> list[dict[str, Any]]:
    result = await session.execute(
        text(
            """
            SELECT
                target_id,
                scan_run_id,
                round_number,
                tool_name AS selected_tool,
                service,
                evidence_type,
                current_risk,
                next_risk,
                current_confidence,
                next_confidence,
                new_findings,
                new_cve,
                new_open_port,
                evidence_delta,
                learning_score,
                round_value,
                feature_vector,
                label_payload,
                dataset_version,
                feature_version,
                label_version,
                created_at
            FROM round_learning_labels
            ORDER BY target_id, round_number, id
            """
        )
    )
    return [_merge_feature_vector(dict(_mapping(row))) for row in result.fetchall()]


def build_feature_matrix(dataset: list[dict[str, Any]]) -> list[list[Any]]:
    matrix: list[list[Any]] = []
    for row in dataset:
        matrix.append(
            [
                row.get("open_port_count", 0),
                row.get("vuln_count", row.get("new_findings", 0)),
                row.get("avg_cvss", 0.0),
                row.get("has_kev", False),
                row.get("service_count", 0),
                row.get("evidence_count", row.get("evidence_delta", 0)),
                row.get("current_round", row.get("round_number", 0)),
                row.get("max_round", 0),
                row.get("learning_score", 0.5),
                row.get("waf_detected", False),
                row.get("candidate_count", 0),
                row.get("selected_tool"),
                row.get("offline_prior", 0.5),
                row.get("ucb_score", 0.0),
                row.get("hybrid_score", 0.0),
            ]
        )
    return matrix


def build_label_vector(dataset: list[dict[str, Any]]) -> list[float]:
    return [float(row.get("round_value") or 0.0) for row in dataset]


def feature_columns() -> list[str]:
    return list(FEATURE_COLUMNS)


def _mapping(row: Any) -> dict[str, Any]:
    if hasattr(row, "_mapping"):
        return dict(row._mapping)
    if isinstance(row, dict):
        return row
    return dict(row)


def _merge_feature_vector(row: dict[str, Any]) -> dict[str, Any]:
    feature_vector = row.get("feature_vector")
    if isinstance(feature_vector, dict):
        for key, value in feature_vector.items():
            row.setdefault(key, value)
    return row
