"""Offline Gradient Boosting training.

This module is intentionally not imported by runtime decision code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from worker.feature_builder import FEATURE_COLUMNS, FEATURE_VECTOR_VERSION
from worker.model_readiness import check_model_readiness
from worker.round_learning_label import LABEL_VERSION
from worker.training_repository import DATASET_VERSION


ALGORITHM = "GradientBoostingClassifier"


@dataclass
class GBMModel:
    estimator: Any
    feature_columns: list[str]
    categorical_maps: dict[str, dict[str, int]]
    dataset_version: str = DATASET_VERSION
    feature_version: str = FEATURE_VECTOR_VERSION
    label_version: str = LABEL_VERSION
    algorithm: str = ALGORITHM


@dataclass(frozen=True)
class TrainingResult:
    model: GBMModel
    training_samples: int
    label_distribution: dict[str, int]
    metadata: dict[str, Any]


class GBMTrainer:
    def __init__(self, *, random_state: int = 42):
        self.random_state = random_state

    def train(self, dataset: list[dict[str, Any]]) -> TrainingResult:
        readiness = check_model_readiness(dataset)
        if not readiness.ready:
            raise ValueError(f"Dataset not ready for GBM training: {', '.join(readiness.reasons)}")

        categorical_maps = build_categorical_maps(dataset)
        x = build_numeric_feature_matrix(dataset, categorical_maps)
        y = build_binary_label_vector(dataset)
        estimator, sklearn_available = _make_estimator(self.random_state)
        estimator.fit(x, y)
        model = GBMModel(
            estimator=estimator,
            feature_columns=list(FEATURE_COLUMNS),
            categorical_maps=categorical_maps,
        )
        distribution = {
            "valuable": sum(1 for value in y if value == 1),
            "not_valuable": sum(1 for value in y if value == 0),
        }
        return TrainingResult(
            model=model,
            training_samples=len(dataset),
            label_distribution=distribution,
            metadata={
                "algorithm": ALGORITHM,
                "dataset_version": DATASET_VERSION,
                "feature_version": FEATURE_VECTOR_VERSION,
                "label_version": LABEL_VERSION,
                "training_samples": len(dataset),
                "experimental": len(dataset) < 1000,
                "sklearn_available": sklearn_available,
            },
        )


def build_categorical_maps(dataset: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    values = sorted({str(row.get("selected_tool") or "") for row in dataset})
    return {"selected_tool": {value: index for index, value in enumerate(values)}}


def build_numeric_feature_matrix(
    dataset: list[dict[str, Any]],
    categorical_maps: dict[str, dict[str, int]] | None = None,
) -> list[list[float]]:
    categorical_maps = categorical_maps or build_categorical_maps(dataset)
    matrix: list[list[float]] = []
    for row in dataset:
        matrix.append([_numeric_value(row, column, categorical_maps) for column in FEATURE_COLUMNS])
    return matrix


def build_binary_label_vector(dataset: list[dict[str, Any]]) -> list[int]:
    return [1 if float(row.get("round_value") or 0.0) > 0 else 0 for row in dataset]


def _numeric_value(row: dict[str, Any], column: str, categorical_maps: dict[str, dict[str, int]]) -> float:
    if column == "selected_tool":
        value = str(row.get(column) or "")
        return float(categorical_maps.get(column, {}).get(value, -1))
    value = row.get(column)
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _make_estimator(random_state: int) -> tuple[Any, bool]:
    try:
        from sklearn.ensemble import GradientBoostingClassifier

        return GradientBoostingClassifier(random_state=random_state), True
    except ImportError:
        return OfflineGradientBoostingClassifier(), False


class OfflineGradientBoostingClassifier:
    """Small sklearn-compatible fallback for offline tests when sklearn is absent."""

    def __init__(self):
        self.feature_importances_: list[float] = []
        self.positive_centroid: list[float] = []
        self.negative_centroid: list[float] = []

    def fit(self, x: list[list[float]], y: list[int]) -> "OfflineGradientBoostingClassifier":
        if not x:
            self.feature_importances_ = []
            return self
        width = len(x[0])
        positives = [row for row, label in zip(x, y, strict=False) if label == 1]
        negatives = [row for row, label in zip(x, y, strict=False) if label == 0]
        self.positive_centroid = _centroid(positives or x, width)
        self.negative_centroid = _centroid(negatives or x, width)
        self.feature_importances_ = [
            abs(self.positive_centroid[index] - self.negative_centroid[index])
            for index in range(width)
        ]
        total = sum(self.feature_importances_) or 1.0
        self.feature_importances_ = [value / total for value in self.feature_importances_]
        return self

    def predict(self, x: list[list[float]]) -> list[int]:
        return [1 if self._positive_probability(row) >= 0.5 else 0 for row in x]

    def predict_proba(self, x: list[list[float]]) -> list[list[float]]:
        probabilities = []
        for row in x:
            positive = self._positive_probability(row)
            probabilities.append([1 - positive, positive])
        return probabilities

    def _positive_probability(self, row: list[float]) -> float:
        positive_distance = _distance(row, self.positive_centroid)
        negative_distance = _distance(row, self.negative_centroid)
        total = positive_distance + negative_distance
        if total == 0:
            return 0.5
        return negative_distance / total


def _centroid(rows: list[list[float]], width: int) -> list[float]:
    return [
        sum(row[index] for row in rows) / len(rows)
        for index in range(width)
    ]


def _distance(left: list[float], right: list[float]) -> float:
    return sum((a - b) ** 2 for a, b in zip(left, right, strict=False)) ** 0.5
