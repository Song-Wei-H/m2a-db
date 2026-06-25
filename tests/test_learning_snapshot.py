from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models import DecisionScore
from worker.analysis_pipeline import analyze_tool_result_and_generate_task


class FakeAsyncSessionContext:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeScalarResult:
    def scalar_one_or_none(self):
        return None

    def scalars(self):
        return self

    def all(self):
        return []


def make_fake_session():
    session = MagicMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.get = AsyncMock(return_value=None)
    session.execute = AsyncMock(return_value=FakeScalarResult())
    session.begin = MagicMock(return_value=FakeAsyncSessionContext(session))
    return session


@pytest.mark.asyncio
async def test_decision_snapshot_contains_learning_metadata():
    fake_session = make_fake_session()
    with patch("worker.analysis_pipeline.get_next_tool_task", new_callable=AsyncMock) as mock_next, \
         patch("worker.analysis_pipeline.async_session", return_value=FakeAsyncSessionContext(fake_session)), \
         patch("worker.analysis_pipeline.get_learning_feedback", new_callable=AsyncMock) as mock_feedback, \
         patch("worker.analysis_pipeline.summarize_cve_risk", new_callable=AsyncMock) as mock_cve:

        mock_next.return_value = {"action": "tool_task_created", "tool_task_id": 44}
        mock_feedback.return_value = {"success_rate": 0.7, "false_positive_rate": 0.0}
        mock_cve.return_value = MagicMock(
            max_cvss=5.0,
            max_epss=0.2,
            has_kev=False,
            total_score=3.0,
            best_cve=None,
            cve_count=0,
            best_match_type=None,
            best_match_confidence=None,
        )

        results = await analyze_tool_result_and_generate_task(
            target_id=1,
            open_port_id=1,
            tool_name="httpx_basic",
            parsed_output={"status_codes": [200], "urls": ["http://192.0.2.22"]},
            raw_output="http://192.0.2.22 [200]",
            tool_result_id=99,
            ctx=None,
            decision_score_id=None,
        )

    decision_result = results[0]["decision_result"]
    assert decision_result["candidate_tools"] == ["nuclei_safe"]
    assert decision_result["selection_strategy"] in {"LearningRanking", "DeterministicRanking"}
    assert decision_result["learning_context"]["previous_tool"] == "httpx_basic"
    assert decision_result["tool_rank_scores"][0]["tool_name"] == "nuclei_safe"

    added_decisions = [
        call.args[0]
        for call in fake_session.add.call_args_list
        if isinstance(call.args[0], DecisionScore)
    ]
    assert added_decisions
    snapshot = added_decisions[-1].input_snapshot
    assert snapshot["candidate_tools"] == ["nuclei_safe"]
    assert snapshot["learning_context"]["previous_tool"] == "httpx_basic"
    assert snapshot["selection_reason"]
