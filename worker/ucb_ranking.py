"""UCB1 advisory ranking strategy."""

from __future__ import annotations

import math

from worker.learning_context import LearningContext
from worker.learning_statistics import LearningStatisticsProvider
from worker.tool_ranking import ToolRank


class UCBRanking:
    def __init__(self, statistics: LearningStatisticsProvider, exploration_c: float = 1.414):
        self.statistics = statistics
        self.exploration_c = exploration_c

    async def rank_tools(
        self,
        *,
        candidate_tools: list[str],
        context: LearningContext,
    ) -> list[ToolRank]:
        context_stats = await self.statistics.get_tool_statistics(context)
        total_observations = await self.statistics.get_total_observations(context)
        total_for_log = max(total_observations, 1)

        ranked: list[ToolRank] = []
        for index, tool_name in enumerate(candidate_tools):
            row = context_stats.get(tool_name, {})
            observations = int(row.get("total_runs") or 0)
            avg_reward = float(row.get("avg_learning_score") or 0.5)

            if observations <= 0:
                exploration = self.exploration_c * math.sqrt(math.log(total_for_log + 1.0))
            else:
                exploration = self.exploration_c * math.sqrt(
                    math.log(total_for_log + 1.0) / observations
                )

            score = round(avg_reward + exploration - index * 0.0001, 6)
            ranked.append(
                ToolRank(
                    tool_name=tool_name,
                    score=score,
                    reason=(
                        f"ucb1 avg_reward={avg_reward:.3f}; "
                        f"observations={observations}; total={total_observations}"
                    ),
                    metadata={
                        "ucb_score": score,
                        "avg_reward": avg_reward,
                        "tool_context_observations": observations,
                        "total_context_observations": total_observations,
                    },
                )
            )

        return sorted(ranked, key=lambda item: item.score, reverse=True)
