"""Local-file offline model registry."""

from __future__ import annotations

import json
import pickle
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from worker.gbm_trainer import GBMModel


@dataclass(frozen=True)
class RegisteredModel:
    model_version: str
    model_path: Path
    metadata_path: Path
    metadata: dict[str, Any]


class LocalModelRegistry:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    def save_model(
        self,
        model: GBMModel,
        *,
        model_version: str,
        dataset_size: int,
        evaluation_result: dict[str, Any],
    ) -> RegisteredModel:
        model_dir = self.root / model_version
        model_dir.mkdir(parents=True, exist_ok=True)
        model_path = model_dir / "model.pkl"
        metadata_path = model_dir / "model_metadata.json"
        metadata = {
            "model_version": model_version,
            "training_time": datetime.now(UTC).isoformat(),
            "dataset_version": model.dataset_version,
            "feature_version": model.feature_version,
            "label_version": model.label_version,
            "training_samples": dataset_size,
            "algorithm": model.algorithm,
            "evaluation_result": evaluation_result,
        }

        with model_path.open("wb") as handle:
            pickle.dump(model, handle)
        metadata_path.write_text(json.dumps(metadata, indent=2, default=str), encoding="utf-8")
        return RegisteredModel(
            model_version=model_version,
            model_path=model_path,
            metadata_path=metadata_path,
            metadata=metadata,
        )

    def load_model(self, model_version: str) -> GBMModel:
        model_path = self.root / model_version / "model.pkl"
        with model_path.open("rb") as handle:
            return pickle.load(handle)

    def load_metadata(self, model_version: str) -> dict[str, Any]:
        metadata_path = self.root / model_version / "model_metadata.json"
        return json.loads(metadata_path.read_text(encoding="utf-8"))
