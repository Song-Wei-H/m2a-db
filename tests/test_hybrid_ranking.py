from types import SimpleNamespace

import pytest

from worker.hybrid_ranking import HybridRanking
from worker.learning_context import LearningContext


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
async def test_hybrid_ranking_cold_start_uses_prior_weight():
    ranked = await HybridRanking(
        statistics=FakeStatistics(
            {"nuclei_safe": {"total_runs": 0, "avg_learning_score": 0.5}},
            total=0,
        )
    ).rank_tools(candidate_tools=["nuclei_safe"], context=context())

    assert ranked[0].metadata["prior_weight"] == 0.70
    assert ranked[0].metadata["online_weight"] == 0.30
    assert ranked[0].metadata["offline_prior_score"] == 0.85
    assert ranked[0].metadata["ranking_algorithm"] == "HybridRanking(UCB1)"


@pytest.mark.asyncio
async def test_hybrid_ranking_switches_weight_after_observations():
    ranked = await HybridRanking(
        statistics=FakeStatistics(
            {"nuclei_safe": {"total_runs": 20, "avg_learning_score": 0.8}},
            total=20,
        )
    ).rank_tools(candidate_tools=["nuclei_safe"], context=context())

    assert ranked[0].metadata["prior_weight"] == 0.30
    assert ranked[0].metadata["online_weight"] == 0.70


@pytest.mark.asyncio
async def test_hybrid_ranking_does_not_inject_candidates():
    ranked = await HybridRanking(
        statistics=FakeStatistics({}, total=0)
    ).rank_tools(candidate_tools=["nuclei_safe"], context=context())

    assert [item.tool_name for item in ranked] == ["nuclei_safe"]
