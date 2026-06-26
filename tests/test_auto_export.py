from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from worker.auto_loop import get_next_tool_task


class FakeScalarResult:
    def __init__(self, value=None):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class FakeAsyncSessionContext:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, tb):
        return False


@pytest.mark.asyncio
async def test_auto_loop_schedules_report_export_when_target_completed():
    target = MagicMock(id=18, current_round=5, max_round=5, status="running")
    session = MagicMock()
    session.get = AsyncMock(return_value=target)
    session.execute = AsyncMock(side_effect=[FakeScalarResult(None), FakeScalarResult(None), FakeScalarResult(None)])
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.begin = MagicMock(return_value=FakeAsyncSessionContext(session))

    with patch("worker.auto_loop.async_session", return_value=FakeAsyncSessionContext(session)), patch(
        "worker.auto_loop._schedule_report_export"
    ) as mock_schedule:
        result = await get_next_tool_task(
            18,
            None,
            {"recommended_tool": None, "recommended_action": "stop", "decision_score_id": 1},
        )

    assert result["action"] == "stop"
    assert result["target_completed"] is True
    mock_schedule.assert_called_once_with(18)
