"""Hybrid offline-prior plus online-UCB advisory ranking."""

from __future__ import annotations

from worker.learning_context import LearningContext
from worker.learning_statistics import LearningStatisticsProvider
from worker.offline_knowledge_prior import OfflineKnowledgePrior
from worker.tool_ranking import ToolRank
from worker.ucb_ranking import UCBRanking


class HybridRanking:
    ranking_version = "hybrid-ranking-v1"
    ranking_algorithm = "HybridRanking(UCB1)"

    def __init__(
        self,
        *,
        statistics: LearningStatisticsProvider,
        offline_prior: OfflineKnowledgePrior | None = None,
        ucb_ranking: UCBRanking | None = None,
    ):
        self.statistics = statistics
        self.offline_prior = offline_prior or OfflineKnowledgePrior()
        self.ucb_ranking = ucb_ranking or UCBRanking(statistics)

    async def rank_tools(
        self,
        *,
        candidate_tools: list[str],
        context: LearningContext,
    ) -> list[ToolRank]:
        total_observations = await self.statistics.get_total_observations(context)
        if total_observations < 10:
            prior_weight = 0.70
            online_weight = 0.30
        else:
            prior_weight = 0.30
            online_weight = 0.70

        prior_scores = await self.offline_prior.score_candidates(
            candidate_tools=candidate_tools,
            context=context,
        )
        ucb_scores = {
            rank.tool_name: rank
            for rank in await self.ucb_ranking.rank_tools(
                candidate_tools=candidate_tools,
                context=context,
            )
        }

        ranked: list[ToolRank] = []
        for index, tool_name in enumerate(candidate_tools):
            prior_score = float(prior_scores.get(tool_name, 0.5))
            ucb_score = float(ucb_scores.get(tool_name, ToolRank(tool_name, 0.5, "")).score)
            hybrid_score = round(
                prior_weight * prior_score
                + online_weight * ucb_score
                - index * 0.0001,
                6,
            )
            ranked.append(
                ToolRank(
                    tool_name=tool_name,
                    score=hybrid_score,
                    reason=(
                        f"offline_prior={prior_score:.3f}; "
                        f"ucb_score={ucb_score:.3f}; "
                        f"prior_weight={prior_weight:.2f}; online_weight={online_weight:.2f}"
                    ),
                    metadata={
                        "offline_prior_score": prior_score,
                        "ucb_score": ucb_score,
                        "hybrid_score": hybrid_score,
                        "prior_weight": prior_weight,
                        "online_weight": online_weight,
                        "ranking_version": self.ranking_version,
                        "ranking_algorithm": self.ranking_algorithm,
                    },
                )
            )

        return sorted(ranked, key=lambda item: item.score, reverse=True)
