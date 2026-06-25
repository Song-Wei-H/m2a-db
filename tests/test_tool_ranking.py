from types import SimpleNamespace

import pytest

from worker.learning_context import LearningContext
from worker.tool_ranking import DeterministicRanking, LearningRanking


class FakeStatistics:
    async def get_tool_success_rate(self, tool_name, context):
        return {"nuclei_safe": 0.8, "dirb_safe": 0.4}[tool_name]

    async def get_average_learning_score(self, tool_name, context):
        return {"nuclei_safe": 0.75, "dirb_safe": 0.9}[tool_name]

    async def get_recent_learning(self, tool_name):
        return {"recent_score": {"nuclei_safe": 0.85, "dirb_safe": 0.2}[tool_name]}


def context():
    return LearningContext.from_target(
        open_port=SimpleNamespace(port=443, service="https"),
        evidence={"evidence_type": "http_service"},
    )


@pytest.mark.asyncio
async def test_deterministic_ranking_preserves_candidate_order():
    ranked = await DeterministicRanking().rank_tools(
        candidate_tools=["dirb_safe", "nuclei_safe"],
        context=context(),
    )

    assert [item.tool_name for item in ranked] == ["dirb_safe", "nuclei_safe"]


@pytest.mark.asyncio
async def test_learning_ranking_uses_statistics_without_adding_tools():
    ranked = await LearningRanking(FakeStatistics()).rank_tools(
        candidate_tools=["dirb_safe", "nuclei_safe"],
        context=context(),
    )

    assert [item.tool_name for item in ranked] == ["nuclei_safe", "dirb_safe"]
    assert {item.tool_name for item in ranked} == {"dirb_safe", "nuclei_safe"}
    assert all("success_rate=" in item.reason for item in ranked)
