from types import SimpleNamespace

import pytest

from worker.learning_context import LearningContext
from worker.ucb_ranking import UCBRanking


class FakeStatistics:
    def __init__(self, rows, total):
        self.rows = rows
        self.total = total

    async def get_tool_statistics(self, context):
        return self.rows

    async def get_total_observations(self, context):
        return self.total


def context():
    return LearningContext.from_target(
        open_port=SimpleNamespace(port=443, service="https"),
        evidence={"evidence_type": "http_service"},
    )


@pytest.mark.asyncio
async def test_ucb_ranking_prioritizes_zero_observation_exploration_without_nan():
    ranked = await UCBRanking(
        FakeStatistics(
            {
                "nuclei_safe": {"total_runs": 10, "avg_learning_score": 0.9},
                "dirb_safe": {"total_runs": 0, "avg_learning_score": 0.5},
            },
            total=10,
        )
    ).rank_tools(candidate_tools=["nuclei_safe", "dirb_safe"], context=context())

    assert ranked[0].tool_name == "dirb_safe"
    assert all(item.score == item.score for item in ranked)


@pytest.mark.asyncio
async def test_ucb_ranking_handles_high_and_low_reward():
    ranked = await UCBRanking(
        FakeStatistics(
            {
                "nuclei_safe": {"total_runs": 20, "avg_learning_score": 0.9},
                "dirb_safe": {"total_runs": 20, "avg_learning_score": 0.2},
            },
            total=40,
        )
    ).rank_tools(candidate_tools=["nuclei_safe", "dirb_safe"], context=context())

    assert ranked[0].tool_name == "nuclei_safe"
    assert ranked[0].metadata["ucb_score"] >= ranked[1].metadata["ucb_score"]
