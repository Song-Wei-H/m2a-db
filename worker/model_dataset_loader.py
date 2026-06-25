"""Offline dataset loading and split helpers for model experiments."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any

from worker.training_repository import TrainingRepository


@dataclass(frozen=True)
class DatasetSplit:
    train: list[dict[str, Any]]
    validation: list[dict[str, Any]]
    test: list[dict[str, Any]]


async def load_training_dataset(repository: TrainingRepository) -> list[dict[str, Any]]:
    return await repository.load_dataset()


async def load_validation_dataset(repository: TrainingRepository) -> list[dict[str, Any]]:
    dataset = await repository.load_dataset()
    return split_dataset(dataset).validation


async def load_test_dataset(repository: TrainingRepository) -> list[dict[str, Any]]:
    dataset = await repository.load_dataset()
    return split_dataset(dataset).test


def split_dataset(
    dataset: list[dict[str, Any]],
    *,
    train_ratio: float = 0.7,
    validation_ratio: float = 0.15,
    test_ratio: float = 0.15,
    seed: int = 42,
) -> DatasetSplit:
    if round(train_ratio + validation_ratio + test_ratio, 6) != 1.0:
        raise ValueError("Dataset split ratios must sum to 1.0")

    rows = list(dataset)
    random.Random(seed).shuffle(rows)
    train_end = int(len(rows) * train_ratio)
    validation_end = train_end + int(len(rows) * validation_ratio)

    return DatasetSplit(
        train=rows[:train_end],
        validation=rows[train_end:validation_end],
        test=rows[validation_end:],
    )
