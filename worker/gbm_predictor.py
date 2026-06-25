"""Offline-only GBM prediction helpers."""

from __future__ import annotations

from typing import Any

from worker.gbm_trainer import GBMModel, build_numeric_feature_matrix


class GBMPredictor:
    def __init__(self, model: GBMModel):
        self.model = model

    def predict(self, dataset: list[dict[str, Any]]) -> list[int]:
        x = build_numeric_feature_matrix(dataset, self.model.categorical_maps)
        return [int(value) for value in self.model.estimator.predict(x)]

    def predict_probability(self, dataset: list[dict[str, Any]]) -> list[float]:
        x = build_numeric_feature_matrix(dataset, self.model.categorical_maps)
        if not hasattr(self.model.estimator, "predict_proba"):
            return [float(value) for value in self.model.estimator.predict(x)]
        probabilities = self.model.estimator.predict_proba(x)
        return [float(row[1]) if len(row) > 1 else float(row[0]) for row in probabilities]
