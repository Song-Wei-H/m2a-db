"""Offline model evaluation report builder."""

from __future__ import annotations

from typing import Any

from worker.training_data_report import build_training_data_report


def build_model_report(
    *,
    dataset: list[dict[str, Any]],
    train_size: int,
    validation_size: int,
    test_size: int,
    evaluation_result: dict[str, Any],
    model_metadata: dict[str, Any],
) -> dict[str, Any]:
    quality = build_training_data_report(dataset)
    return {
        "dataset_size": len(dataset),
        "train_test_split": {
            "train": train_size,
            "validation": validation_size,
            "test": test_size,
        },
        "label_distribution": quality["label_distribution"],
        "evaluation_metrics": {
            "accuracy": evaluation_result.get("accuracy"),
            "precision": evaluation_result.get("precision"),
            "recall": evaluation_result.get("recall"),
            "f1": evaluation_result.get("f1"),
            "roc_auc": evaluation_result.get("roc_auc"),
        },
        "feature_importance_ranking": evaluation_result.get("feature_importance", []),
        "model_version": model_metadata.get("model_version"),
        "training_time": model_metadata.get("training_time"),
        "experimental_warning": evaluation_result.get("experimental_warning"),
    }
