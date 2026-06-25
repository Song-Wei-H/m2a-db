"""Runtime learning data pipeline.

This pipeline is intentionally side-channel only. It records future training
data and never changes decisions, ranking, tool selection, ToolTask creation, or
governance state.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from worker.feature_builder import FEATURE_VECTOR_VERSION, build_round_features
from worker.round_label_builder import RoundValueLabelBuilder
from worker.round_learning_label import LABEL_VERSION, RoundLearningLabel
from worker.training_repository import DATASET_VERSION, TrainingRepository


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LearningPipelineResult:
    success: bool
    dataset_row_id: int | None = None
    label: RoundLearningLabel | None = None
    feature_vector: dict[str, Any] | None = None
    dataset_version: str = DATASET_VERSION
    feature_version: str = FEATURE_VECTOR_VERSION
    label_version: str = LABEL_VERSION
    warning: str | None = None

    def metadata(self) -> dict[str, Any]:
        return {
            "dataset_version": self.dataset_version,
            "feature_version": self.feature_version,
            "label_version": self.label_version,
            "dataset_row_id": self.dataset_row_id,
            "learning_pipeline_success": self.success,
            "learning_pipeline_warning": self.warning,
        }


class LearningPipeline:
    def __init__(
        self,
        repository: TrainingRepository,
        *,
        label_builder: RoundValueLabelBuilder | None = None,
    ):
        self.repository = repository
        self.label_builder = label_builder or RoundValueLabelBuilder()

    async def record_round(
        self,
        *,
        target_id: int,
        round_number: int,
        tool_name: str | None,
        current_state: dict[str, Any],
        next_state: dict[str, Any],
        target_state: dict[str, Any],
        decision_snapshot: dict[str, Any],
        scan_run_id: int | None = None,
    ) -> LearningPipelineResult:
        try:
            label = self.label_builder.build_label(
                target_id=target_id,
                scan_run_id=scan_run_id,
                round_number=round_number,
                tool_name=tool_name,
                current_state=current_state,
                next_state=next_state,
            )
            feature_vector = build_round_features(
                target_state=target_state,
                decision_snapshot=decision_snapshot,
            )
            dataset_row_id = await self.repository.append_round(
                label=label,
                feature_vector=feature_vector,
                dataset_version=DATASET_VERSION,
                feature_version=feature_vector.get("feature_vector_version", FEATURE_VECTOR_VERSION),
                label_version=LABEL_VERSION,
            )
            return LearningPipelineResult(
                success=True,
                dataset_row_id=dataset_row_id,
                label=label,
                feature_vector=feature_vector,
                feature_version=feature_vector.get("feature_vector_version", FEATURE_VECTOR_VERSION),
            )
        except Exception as exc:
            logger.warning("Learning pipeline failed without blocking execution: %s", exc)
            return LearningPipelineResult(success=False, warning=str(exc))
