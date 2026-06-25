from types import SimpleNamespace

import pytest

from worker.learning_context import LearningContext
from worker.offline_knowledge_prior import OfflineKnowledgePrior


@pytest.mark.asyncio
async def test_offline_prior_scores_only_candidate_tools():
    context = LearningContext.from_target(
        open_port=SimpleNamespace(port=443, service="https"),
        evidence={"evidence_type": "http_service"},
    )

    scores = await OfflineKnowledgePrior().score_candidates(
        candidate_tools=["nuclei_safe"],
        context=context,
    )

    assert scores == {"nuclei_safe": 0.85}
    assert "httpx_basic" not in scores
    assert "dirb_safe" not in scores


@pytest.mark.asyncio
async def test_offline_prior_uses_neutral_score_for_unknown_candidate():
    context = LearningContext.from_target(evidence={"evidence_type": "unknown"})

    scores = await OfflineKnowledgePrior().score_candidates(
        candidate_tools=["custom_allowed_tool"],
        context=context,
    )

    assert scores == {"custom_allowed_tool": 0.5}
