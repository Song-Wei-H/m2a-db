"""Offline model evaluation helpers."""

from __future__ import annotations

from typing import Any

from worker.gbm_predictor import GBMPredictor
from worker.gbm_trainer import GBMModel, build_binary_label_vector


def evaluate_model(model: GBMModel, dataset: list[dict[str, Any]]) -> dict[str, Any]:
    if not dataset:
        return {
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "roc_auc": None,
            "confusion_matrix": [],
            "feature_importance": [],
            "experimental_warning": "No evaluation samples available.",
        }

    predictor = GBMPredictor(model)
    y_true = build_binary_label_vector(dataset)
    y_pred = predictor.predict(dataset)
    probabilities = predictor.predict_probability(dataset)

    importance_values = getattr(model.estimator, "feature_importances_", [])
    feature_importance = sorted(
        [
            {"feature": feature, "importance": float(importance_values[index])}
            for index, feature in enumerate(model.feature_columns)
            if index < len(importance_values)
        ],
        key=lambda item: item["importance"],
        reverse=True,
    )

    return {
        "accuracy": _accuracy(y_true, y_pred),
        "precision": _precision(y_true, y_pred),
        "recall": _recall(y_true, y_pred),
        "f1": _f1(y_true, y_pred),
        "roc_auc": _roc_auc(y_true, probabilities),
        "confusion_matrix": _confusion_matrix(y_true, y_pred),
        "feature_importance": feature_importance,
        "experimental_warning": (
            "Model is experimental; collect more data before runtime use."
            if len(dataset) < 500
            else None
        ),
    }


def _accuracy(y_true: list[int], y_pred: list[int]) -> float:
    return sum(1 for left, right in zip(y_true, y_pred, strict=False) if left == right) / len(y_true)


def _precision(y_true: list[int], y_pred: list[int]) -> float:
    true_positive = sum(1 for left, right in zip(y_true, y_pred, strict=False) if left == right == 1)
    predicted_positive = sum(1 for value in y_pred if value == 1)
    return true_positive / predicted_positive if predicted_positive else 0.0


def _recall(y_true: list[int], y_pred: list[int]) -> float:
    true_positive = sum(1 for left, right in zip(y_true, y_pred, strict=False) if left == right == 1)
    actual_positive = sum(1 for value in y_true if value == 1)
    return true_positive / actual_positive if actual_positive else 0.0


def _f1(y_true: list[int], y_pred: list[int]) -> float:
    precision = _precision(y_true, y_pred)
    recall = _recall(y_true, y_pred)
    return 2 * precision * recall / (precision + recall) if precision + recall else 0.0


def _confusion_matrix(y_true: list[int], y_pred: list[int]) -> list[list[int]]:
    tn = sum(1 for left, right in zip(y_true, y_pred, strict=False) if left == 0 and right == 0)
    fp = sum(1 for left, right in zip(y_true, y_pred, strict=False) if left == 0 and right == 1)
    fn = sum(1 for left, right in zip(y_true, y_pred, strict=False) if left == 1 and right == 0)
    tp = sum(1 for left, right in zip(y_true, y_pred, strict=False) if left == 1 and right == 1)
    return [[tn, fp], [fn, tp]]


def _roc_auc(y_true: list[int], probabilities: list[float]) -> float | None:
    positives = [score for label, score in zip(y_true, probabilities, strict=False) if label == 1]
    negatives = [score for label, score in zip(y_true, probabilities, strict=False) if label == 0]
    if not positives or not negatives:
        return None
    wins = 0.0
    for positive in positives:
        for negative in negatives:
            if positive > negative:
                wins += 1
            elif positive == negative:
                wins += 0.5
    return wins / (len(positives) * len(negatives))
