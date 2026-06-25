import pytest

from worker.feature_builder import FEATURE_VECTOR_VERSION
from worker.round_learning_label import LABEL_VERSION, RoundLearningLabel
from worker.training_repository import DATASET_VERSION, PostgreSQLTrainingRepository


class FakeResult:
    def __init__(self, row=None):
        self.row = row

    def fetchone(self):
        return self.row

    def fetchall(self):
        return []


class FakeSession:
    def __init__(self):
        self.calls = []

    async def execute(self, statement, params=None):
        self.calls.append((str(statement), params or {}))
        if "RETURNING id" in str(statement):
            return FakeResult((123,))
        if "COUNT(*)" in str(statement):
            return FakeResult({"dataset_size": 1, "target_count": 1, "tool_count": 1, "average_round_value": 2.0})
        return FakeResult()


def make_label():
    return RoundLearningLabel(
        target_id=1,
        scan_run_id=None,
        round_number=2,
        tool_name="nuclei_safe",
        service="https",
        evidence_type="vulnerability",
        current_risk=3.0,
        next_risk=6.0,
        current_confidence=0.5,
        next_confidence=0.8,
        new_findings=1,
        new_cve=0,
        new_open_port=0,
        evidence_delta=1,
        learning_score=0.8,
        round_value=3.0,
    )


@pytest.mark.asyncio
async def test_postgresql_training_repository_append_round_persists_versions():
    session = FakeSession()
    repo = PostgreSQLTrainingRepository(session)

    row_id = await repo.append_round(label=make_label(), feature_vector={"selected_tool": "nuclei_safe"})

    assert row_id == 123
    sql, params = session.calls[0]
    assert "round_learning_labels" in sql
    assert params["dataset_version"] == DATASET_VERSION
    assert params["feature_version"] == FEATURE_VECTOR_VERSION
    assert params["label_version"] == LABEL_VERSION


@pytest.mark.asyncio
async def test_postgresql_training_repository_statistics_and_size():
    repo = PostgreSQLTrainingRepository(FakeSession())

    stats = await repo.dataset_statistics()
    size = await repo.dataset_size()

    assert stats["dataset_size"] == 1
    assert size == 1
