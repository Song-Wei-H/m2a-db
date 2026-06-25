"""Training dataset repository interfaces and PostgreSQL implementation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from worker.feature_builder import FEATURE_VECTOR_VERSION
from worker.round_learning_label import LABEL_VERSION, RoundLearningLabel


DATASET_VERSION = "round-dataset-v1"


class TrainingRepository(Protocol):
    async def append_round(
        self,
        *,
        label: RoundLearningLabel,
        feature_vector: dict[str, Any],
        dataset_version: str = DATASET_VERSION,
        feature_version: str = FEATURE_VECTOR_VERSION,
        label_version: str = LABEL_VERSION,
    ) -> int | None:
        ...

    async def append_feature(self, *, dataset_row_id: int | None, feature_vector: dict[str, Any]) -> None:
        ...

    async def append_label(self, *, dataset_row_id: int | None, label: RoundLearningLabel) -> None:
        ...

    async def load_dataset(self) -> list[dict[str, Any]]:
        ...

    async def dataset_statistics(self) -> dict[str, Any]:
        ...

    async def dataset_size(self) -> int:
        ...


class PostgreSQLTrainingRepository:
    """Persist training rows to the local PostgreSQL-backed label table."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def append_round(
        self,
        *,
        label: RoundLearningLabel,
        feature_vector: dict[str, Any],
        dataset_version: str = DATASET_VERSION,
        feature_version: str = FEATURE_VECTOR_VERSION,
        label_version: str = LABEL_VERSION,
    ) -> int | None:
        label_data = label.to_dict()
        label_payload = {
            "new_findings": label.new_findings,
            "new_cve": label.new_cve,
            "new_open_port": label.new_open_port,
            "evidence_delta": label.evidence_delta,
            "round_value": label.round_value,
        }
        result = await self.session.execute(
            text(
                """
                INSERT INTO round_learning_labels (
                    target_id,
                    scan_run_id,
                    round_number,
                    tool_name,
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
                    feature_vector_version,
                    created_at
                )
                VALUES (
                    :target_id,
                    :scan_run_id,
                    :round_number,
                    :tool_name,
                    :service,
                    :evidence_type,
                    :current_risk,
                    :next_risk,
                    :current_confidence,
                    :next_confidence,
                    :new_findings,
                    :new_cve,
                    :new_open_port,
                    :evidence_delta,
                    :learning_score,
                    :round_value,
                    CAST(:feature_vector AS JSONB),
                    CAST(:label_payload AS JSONB),
                    :dataset_version,
                    :feature_version,
                    :label_version,
                    :feature_version,
                    :created_at
                )
                RETURNING id
                """
            ),
            {
                **label_data,
                "feature_vector": _json_text(feature_vector),
                "label_payload": _json_text(label_payload),
                "dataset_version": dataset_version,
                "feature_version": feature_version,
                "label_version": label_version,
                "created_at": datetime.now(UTC),
            },
        )
        row = result.fetchone()
        if row is None:
            return None
        return int(row[0] if not hasattr(row, "_mapping") else row._mapping["id"])

    async def append_feature(self, *, dataset_row_id: int | None, feature_vector: dict[str, Any]) -> None:
        if dataset_row_id is None:
            return
        await self.session.execute(
            text(
                """
                UPDATE round_learning_labels
                SET feature_vector = CAST(:feature_vector AS JSONB),
                    feature_version = :feature_version,
                    feature_vector_version = :feature_version
                WHERE id = :dataset_row_id
                """
            ),
            {
                "dataset_row_id": dataset_row_id,
                "feature_vector": _json_text(feature_vector),
                "feature_version": feature_vector.get("feature_vector_version", FEATURE_VECTOR_VERSION),
            },
        )

    async def append_label(self, *, dataset_row_id: int | None, label: RoundLearningLabel) -> None:
        if dataset_row_id is None:
            return
        payload = label.to_dict()
        await self.session.execute(
            text(
                """
                UPDATE round_learning_labels
                SET label_payload = CAST(:label_payload AS JSONB),
                    label_version = :label_version,
                    round_value = :round_value
                WHERE id = :dataset_row_id
                """
            ),
            {
                "dataset_row_id": dataset_row_id,
                "label_payload": _json_text(payload),
                "label_version": LABEL_VERSION,
                "round_value": label.round_value,
            },
        )

    async def load_dataset(self) -> list[dict[str, Any]]:
        result = await self.session.execute(
            text(
                """
                SELECT
                    id,
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
        return [dict(_mapping(row)) for row in result.fetchall()]

    async def dataset_statistics(self) -> dict[str, Any]:
        result = await self.session.execute(
            text(
                """
                SELECT
                    COUNT(*) AS dataset_size,
                    COUNT(DISTINCT target_id) AS target_count,
                    COUNT(DISTINCT tool_name) AS tool_count,
                    AVG(round_value) AS average_round_value
                FROM round_learning_labels
                """
            )
        )
        row = result.fetchone()
        return dict(_mapping(row)) if row is not None else {}

    async def dataset_size(self) -> int:
        stats = await self.dataset_statistics()
        return int(stats.get("dataset_size") or 0)


def _mapping(row: Any) -> dict[str, Any]:
    if hasattr(row, "_mapping"):
        return dict(row._mapping)
    if isinstance(row, dict):
        return row
    return dict(row)


def _json_text(value: dict[str, Any]) -> str:
    import json

    return json.dumps(value, default=str, sort_keys=True)
