"""Offline prior helper used by hybrid ranking."""

from __future__ import annotations

from worker.learning_context import LearningContext
from worker.offline_knowledge_provider import BuiltinKnowledgeProvider, OfflineKnowledgeProvider


class OfflineKnowledgePrior:
    def __init__(self, provider: OfflineKnowledgeProvider | None = None):
        self.provider = provider or BuiltinKnowledgeProvider()

    async def score_candidates(
        self,
        *,
        candidate_tools: list[str],
        context: LearningContext,
    ) -> dict[str, float]:
        prior = await self.provider.load_prior(context)
        return {
            tool_name: float(prior.get(tool_name, 0.5))
            for tool_name in candidate_tools
        }
