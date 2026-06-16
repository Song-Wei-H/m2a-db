from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models import AutoLoopDecision, ToolTask
from worker.auto_loop import get_next_tool_task


class FakeScalarResult:
    def __init__(self, value=None):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return self

    def all(self):
        if self.value is None:
            return []
        if isinstance(self.value, list):
            return self.value
        return [self.value]


class FakeAsyncSessionContext:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, tb):
        return False


def make_target(*, current_round=1, max_round=5, status="running"):
    return SimpleNamespace(
        id=1,
        current_round=current_round,
        max_round=max_round,
        status=status,
    )


def make_session(target, execute_results=None):
    session = MagicMock()
    session.get = AsyncMock(return_value=target)
    session.add = MagicMock()
    session.flush = AsyncMock()
    results = list(execute_results or [])

    async def fake_execute(*args, **kwargs):
        if results:
            return FakeScalarResult(results.pop(0))
        return FakeScalarResult(None)

    session.execute = AsyncMock(side_effect=fake_execute)
    session.begin = MagicMock(return_value=FakeAsyncSessionContext(session))
    return session


@pytest.mark.asyncio
async def test_max_rounds_stop_execution_without_tool_task():
    session = make_session(
        make_target(current_round=5, max_round=5),
        execute_results=[
            None,
            None,
            None,
            None,
        ],
    )

    with patch("worker.auto_loop.async_session", return_value=FakeAsyncSessionContext(session)), \
         patch("worker.auto_loop.generate_tool_task", new_callable=AsyncMock) as mock_generate:
        result = await get_next_tool_task(
            1,
            10,
            {"recommended_tool": "httpx_basic", "recommended_action": "continue"},
        )

    assert result["action"] == "stop"
    assert result["stop_reason"] == "max_round_reached"
    assert result["reason"] == "Maximum round limit reached"
    mock_generate.assert_not_awaited()
    loop_decision = session.add.call_args_list[0].args[0]
    assert isinstance(loop_decision, AutoLoopDecision)
    assert loop_decision.stop_reason == "Maximum round limit reached"


@pytest.mark.asyncio
async def test_duplicate_tool_prevention_stops_without_tool_task():
    existing_task = ToolTask(id=55, target_id=1, open_port_id=10, tool_name="httpx_basic", status="completed")
    session = make_session(
        make_target(current_round=2, max_round=5),
        execute_results=[
            existing_task,
            None,
            None,
            None,
        ],
    )

    with patch("worker.auto_loop.async_session", return_value=FakeAsyncSessionContext(session)), \
         patch("worker.auto_loop.generate_tool_task", new_callable=AsyncMock) as mock_generate:
        result = await get_next_tool_task(
            1,
            10,
            {"recommended_tool": "httpx_basic", "recommended_action": "continue"},
        )

    assert result["action"] == "stop"
    assert result["stop_reason"] == "duplicate_tool"
    assert result["reason"] == "Duplicate tool execution prevented"
    assert result["existing_task_id"] == 55
    mock_generate.assert_not_awaited()


@pytest.mark.asyncio
async def test_stop_condition_from_decision_stops_without_tool_task():
    session = make_session(
        make_target(current_round=2, max_round=5),
        execute_results=[
            None,
            None,
            None,
            None,
        ],
    )

    with patch("worker.auto_loop.async_session", return_value=FakeAsyncSessionContext(session)), \
         patch("worker.auto_loop.generate_tool_task", new_callable=AsyncMock) as mock_generate:
        result = await get_next_tool_task(
            1,
            10,
            {"recommended_tool": None, "recommended_action": "stop"},
        )

    assert result["action"] == "stop"
    assert result["stop_reason"] == "no_next_tool"
    assert result["reason"] == "No next tool selected"
    mock_generate.assert_not_awaited()


@pytest.mark.asyncio
async def test_completed_target_stops_without_tool_task():
    session = make_session(
        make_target(current_round=2, max_round=5, status="completed"),
        execute_results=[
            None,
            None,
            None,
            None,
        ],
    )

    with patch("worker.auto_loop.async_session", return_value=FakeAsyncSessionContext(session)), \
         patch("worker.auto_loop.generate_tool_task", new_callable=AsyncMock) as mock_generate:
        result = await get_next_tool_task(
            1,
            10,
            {"recommended_tool": "httpx_basic", "recommended_action": "continue"},
        )

    assert result["action"] == "stop"
    assert result["stop_reason"] == "target_completed"
    assert result["reason"] == "Target already completed"
    mock_generate.assert_not_awaited()


@pytest.mark.asyncio
async def test_approval_gate_creates_pending_approval_tool_task():
    session = make_session(
        make_target(current_round=2, max_round=5),
        execute_results=[
            None,
        ],
    )

    with patch("worker.auto_loop.async_session", return_value=FakeAsyncSessionContext(session)), \
         patch("worker.auto_loop.generate_tool_task", new_callable=AsyncMock) as mock_generate:
        mock_generate.return_value = {
            "action": "tool_task_created",
            "tool_task_id": 77,
            "approval_required": True,
            "approval_status": "pending_approval",
        }

        result = await get_next_tool_task(
            1,
            10,
            {
                "recommended_tool": "nuclei_safe",
                "recommended_action": "verify",
                "requires_approval": True,
                "decision_score_id": 30,
            },
        )

    assert result["action"] == "tool_task_created"
    assert result["approval_required"] is True
    assert result["approval_status"] == "pending_approval"
    mock_generate.assert_awaited_once()
    decision_result = mock_generate.await_args.kwargs["decision_result"]
    assert decision_result["requires_approval"] is True


@pytest.mark.asyncio
async def test_valid_tool_creates_new_tool_task():
    session = make_session(
        make_target(current_round=2, max_round=5),
        execute_results=[
            None,
        ],
    )

    with patch("worker.auto_loop.async_session", return_value=FakeAsyncSessionContext(session)), \
         patch("worker.auto_loop.generate_tool_task", new_callable=AsyncMock) as mock_generate:
        mock_generate.return_value = {
            "action": "tool_task_created",
            "tool_task_id": 88,
            "approval_required": False,
            "approval_status": "not_required",
        }

        result = await get_next_tool_task(
            1,
            10,
            {
                "recommended_tool": "httpx_basic",
                "recommended_action": "continue",
                "decision_score_id": 31,
            },
        )

    assert result["action"] == "tool_task_created"
    assert result["tool_task_id"] == 88
    assert result["approval_required"] is False
    assert result["approval_status"] == "not_required"
    mock_generate.assert_awaited_once()
