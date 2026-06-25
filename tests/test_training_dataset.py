from types import SimpleNamespace

import pytest

from worker.training_data_report import build_training_data_report
from worker.training_dataset_builder import (
    build_dataset,
    build_feature_matrix,
    build_label_vector,
    feature_columns,
)


class FakeResult:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return self.rows


class FakeSession:
    async def execute(self, statement):
        return FakeResult(
            [
                SimpleNamespace(
                    _mapping={
                        "target_id": 1,
                        "scan_run_id": None,
                        "round_number": 1,
                        "selected_tool": "httpx_basic",
                        "service": "https",
                        "evidence_type": "http_service",
                        "current_risk": 1.0,
                        "next_risk": 4.0,
                        "current_confidence": 0.4,
                        "next_confidence": 0.8,
                        "new_findings": 1,
                        "new_cve": 0,
                        "new_open_port": 0,
                        "evidence_delta": 1,
                        "learning_score": 0.8,
                        "round_value": 3.0,
                    }
                )
            ]
        )


@pytest.mark.asyncio
async def test_training_dataset_export_helpers():
    dataset = await build_dataset(FakeSession())

    assert dataset[0]["target_id"] == 1
    assert build_label_vector(dataset) == [3.0]
    matrix = build_feature_matrix(dataset)
    assert len(matrix) == 1
    assert len(matrix[0]) == len(feature_columns())


def test_training_data_quality_report():
    report = build_training_data_report(
        [
            {"round_value": 3.0, "open_port_count": 1, "selected_tool": "httpx_basic"},
            {"round_value": 0.0, "open_port_count": None, "selected_tool": "dirb_safe"},
            {"round_value": -1.0, "open_port_count": 1, "selected_tool": "nuclei_safe"},
        ]
    )

    assert report["available_samples"] == 3
    assert report["label_distribution"] == {"positive": 1, "zero": 1, "negative": 1}
    assert report["average_round_value"] == pytest.approx(2 / 3)
    assert report["missing_feature_rate"] > 0
    assert report["suitable_for_training"] is False
