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
    def __init__(self, rows=None):
        self.rows = rows or []

    def scalars(self):
        return self

    def all(self):
        return self.rows


def make_fake_session():
    session = MagicMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.get = AsyncMock(return_value=None)
    session.execute = AsyncMock(return_value=FakeScalarResult())
    session.begin = MagicMock(return_value=FakeAsyncSessionContext(session))
    return session


@pytest.mark.asyncio
async def test_tool_result_flows_through_risk_engine_v3_to_tool_task():
    fake_session = make_fake_session()

    with patch("worker.analysis_pipeline.async_session", return_value=FakeAsyncSessionContext(fake_session)), patch(
        "worker.analysis_pipeline.get_learning_feedback", new_callable=AsyncMock
    ) as mock_feedback, patch("worker.analysis_pipeline.get_next_tool_task", new_callable=AsyncMock) as mock_next_task:
        mock_feedback.return_value = {"success_rate": 0.85, "false_positive_rate": 0.0}
        mock_next_task.return_value = {
            "action": "tool_task_created",
            "tool_task_id": 77,
            "tool_name": "nuclei_safe",
        }

        results = await analyze_tool_result_and_generate_task(
            target_id=1,
            open_port_id=10,
            tool_name="httpx_basic",
            parsed_output={
                "parser_success": True,
                "status_codes": [200],
                "services": [{"url": "https://example.com", "status_code": 200}],
                "service": "https",
                "port": 443,
            },
            raw_output="https://example.com [200]",
            tool_result_id=99,
            decision_score_id=55,
        )

    added_decisions = [
        call.args[0]
        for call in fake_session.add.call_args_list
        if isinstance(call.args[0], DecisionScore)
    ]
    assert len(results) == 1
    assert added_decisions

    decision = added_decisions[0]
    assert decision.reason == "Risk Engine v3 generated learning-adjusted risk"
    assert decision.risk_score == decision.adjusted_risk_score
    assert decision.base_risk_score is not None
    assert decision.confidence_score is not None
    assert decision.learning_adjustment > 0
    assert decision.evidence_adjustment > 0
    assert decision.next_tool == "nuclei_safe"
    assert decision.mitre_phase == "Initial Access"
    assert decision.mitre_technique == "T1190"
    assert decision.reasoning[0]["engine"] == "risk_engine_v3"

    mock_next_task.assert_awaited_once()
    task_call = mock_next_task.await_args.kwargs
    assert task_call["target_id"] == 1
    assert task_call["open_port_id"] == 10
    assert task_call["decision_result"]["recommended_tool"] == "nuclei_safe"
    assert task_call["decision_result"]["decision_score_id"] == decision.id
    assert results[0]["task_result"]["action"] == "tool_task_created"
