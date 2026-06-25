"""Advisory-only tool ranking interfaces."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from worker.learning_context import LearningContext
from worker.learning_statistics import LearningStatisticsProvider


@dataclass(frozen=True)
class ToolRank:
    tool_name: str
    score: float
    reason: str


class ToolRankingStrategy(Protocol):
    async def rank_tools(
        self,
        *,
        candidate_tools: list[str],
        context: LearningContext,
    ) -> list[ToolRank]:
        ...


class DeterministicRanking:
    async def rank_tools(
        self,
        *,
        candidate_tools: list[str],
        context: LearningContext,
    ) -> list[ToolRank]:
        return [
            ToolRank(tool_name=tool_name, score=1.0 - index * 0.001, reason="deterministic_order")
            for index, tool_name in enumerate(candidate_tools)
        ]


class LearningRanking:
    def __init__(self, statistics: LearningStatisticsProvider):
        self.statistics = statistics

    async def rank_tools(
        self,
        *,
        candidate_tools: list[str],
        context: LearningContext,
    ) -> list[ToolRank]:
        ranked: list[ToolRank] = []
        for index, tool_name in enumerate(candidate_tools):
            success_rate = await self.statistics.get_tool_success_rate(tool_name, context)
            learning_score = await self.statistics.get_average_learning_score(tool_name, context)
            recent = await self.statistics.get_recent_learning(tool_name)
            recent_score = float(recent.get("recent_score", 0.5))
            score = round(
                success_rate * 0.45
                + learning_score * 0.40
                + recent_score * 0.15
                - index * 0.0001,
                6,
            )
            ranked.append(
                ToolRank(
                    tool_name=tool_name,
                    score=score,
                    reason=(
                        f"success_rate={success_rate:.3f}; "
                        f"learning_score={learning_score:.3f}; "
                        f"recent_score={recent_score:.3f}"
                    ),
                )
            )
        return sorted(ranked, key=lambda item: item.score, reverse=True)
