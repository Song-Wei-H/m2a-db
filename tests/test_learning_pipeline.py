import pytest

from worker.learning_pipeline import LearningPipeline
from worker.training_repository import DATASET_VERSION


class InMemoryRepository:
    def __init__(self):
        self.rows = []

    async def append_round(self, *, label, feature_vector, dataset_version, feature_version, label_version):
        self.rows.append(
            {
                "label": label,
                "feature_vector": feature_vector,
                "dataset_version": dataset_version,
                "feature_version": feature_version,
                "label_version": label_version,
            }
        )
        return len(self.rows)

    async def append_feature(self, *, dataset_row_id, feature_vector):
        return None

    async def append_label(self, *, dataset_row_id, label):
        return None

    async def load_dataset(self):
        return self.rows

    async def dataset_statistics(self):
        return {"dataset_size": len(self.rows)}

    async def dataset_size(self):
        return len(self.rows)


class FailingRepository(InMemoryRepository):
    async def append_round(self, **kwargs):
        raise RuntimeError("repository unavailable")


@pytest.mark.asyncio
async def test_learning_pipeline_runtime_auto_writes_feature_label_dataset():
    repo = InMemoryRepository()
    pipeline = LearningPipeline(repo)

    result = await pipeline.record_round(
        target_id=1,
        scan_run_id=None,
        round_number=2,
        tool_name="httpx_basic",
        current_state={"finding_count": 0},
        next_state={"finding_count": 1, "service": "https", "risk_score": 5.0},
        target_state={"current_round": 2, "max_round": 5, "evidence_count": 1},
        decision_snapshot={
            "candidate_tools": ["nuclei_safe"],
            "selected_tool": "nuclei_safe",
            "tool_rank_scores": [{"tool_name": "nuclei_safe", "hybrid_score": 0.9}],
        },
    )

    assert result.success is True
    assert result.dataset_row_id == 1
    assert result.metadata()["dataset_version"] == DATASET_VERSION
    assert repo.rows[0]["label"].round_value > 0
    assert repo.rows[0]["feature_vector"]["selected_tool"] == "nuclei_safe"


@pytest.mark.asyncio
async def test_learning_pipeline_repository_failure_is_non_blocking():
    result = await LearningPipeline(FailingRepository()).record_round(
        target_id=1,
        round_number=1,
        tool_name="httpx_basic",
        current_state={},
        next_state={},
        target_state={},
        decision_snapshot={},
    )

    assert result.success is False
    assert result.dataset_row_id is None
    assert "repository unavailable" in result.warning


@pytest.mark.asyncio
async def test_learning_pipeline_is_provider_independent():
    repo = InMemoryRepository()
    pipeline = LearningPipeline(repo)

    await pipeline.record_round(
        target_id=1,
        round_number=1,
        tool_name="dirb_safe",
        current_state={},
        next_state={"finding_count": 1},
        target_state={},
        decision_snapshot={"selection_strategy": "HTBKnowledgeProvider"},
    )

    assert await repo.dataset_size() == 1
