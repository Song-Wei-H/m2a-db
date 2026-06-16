from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from worker.auto_loop import finalize_target_if_idle, get_next_tool_task


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


def target(*, current_round=3, max_round=5, status="running"):
    return SimpleNamespace(id=18, current_round=current_round, max_round=max_round, status=status)


def port(service="ssl/http", port_number=443):
    return SimpleNamespace(id=17, target_id=18, service=service, port=port_number)


def task(tool_name, status="completed", task_id=1):
    return SimpleNamespace(id=task_id, target_id=18, open_port_id=17, tool_name=tool_name, status=status)


def session_for_get_next(*, execute_results, target_row=None, port_row=None):
    session = MagicMock()
    session.get = AsyncMock(side_effect=[target_row or target(), port_row or port()])
    session.execute = AsyncMock(side_effect=[FakeScalarResult(value) for value in execute_results])
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.begin = MagicMock(return_value=FakeAsyncSessionContext(session))
    return session


@pytest.mark.asyncio
async def test_httpx_basic_completed_on_http_service_creates_nuclei_safe():
    session = session_for_get_next(
        execute_results=[
            86,
            None,
            None,
        ]
    )

    with patch("worker.auto_loop.async_session", return_value=FakeAsyncSessionContext(session)), patch(
        "worker.auto_loop.generate_tool_task", new_callable=AsyncMock
    ) as mock_generate:
        mock_generate.return_value = {
            "action": "tool_task_created",
            "tool_task_id": 100,
            "approval_required": True,
            "approval_status": "pending_approval",
        }

        result = await get_next_tool_task(
            18,
            17,
            {"recommended_tool": None, "recommended_action": "stop", "decision_score_id": 55},
        )

    assert result["action"] == "tool_task_created"
    decision = mock_generate.await_args.kwargs["decision_result"]
    assert decision["recommended_tool"] == "nuclei_safe"
    assert decision["requires_approval"] is True


@pytest.mark.asyncio
async def test_target_not_completed_after_httpx_when_nuclei_missing():
    session = MagicMock()
    session.get = AsyncMock(side_effect=[target(), port()])
    session.execute = AsyncMock(
        side_effect=[
            FakeScalarResult(None),
            FakeScalarResult([port()]),
            FakeScalarResult(86),
            FakeScalarResult(None),
            FakeScalarResult(None),
        ]
    )

    completed = await finalize_target_if_idle(18, session=session)

    assert completed is False
    update_calls = [call for call in session.execute.await_args_list if "UPDATE targets" in str(call.args[0])]
    assert update_calls == []


@pytest.mark.asyncio
async def test_nuclei_completed_creates_dirb_safe():
    session = session_for_get_next(
        execute_results=[
            task("nuclei_safe", "completed", 200),
            86,
            task("nuclei_safe", "completed", 200),
            None,
            None,
        ]
    )

    with patch("worker.auto_loop.async_session", return_value=FakeAsyncSessionContext(session)), patch(
        "worker.auto_loop.generate_tool_task", new_callable=AsyncMock
    ) as mock_generate:
        mock_generate.return_value = {
            "action": "tool_task_created",
            "tool_task_id": 101,
            "approval_required": True,
            "approval_status": "pending_approval",
        }

        result = await get_next_tool_task(
            18,
            17,
            {"recommended_tool": "nuclei_safe", "recommended_action": "verify", "decision_score_id": 56},
        )

    assert result["action"] == "tool_task_created"
    decision = mock_generate.await_args.kwargs["decision_result"]
    assert decision["recommended_tool"] == "dirb_safe"


@pytest.mark.asyncio
async def test_target_completes_after_http_depth_tools_completed():
    session = MagicMock()
    session.get = AsyncMock(side_effect=[target(), port()])
    session.execute = AsyncMock(
        side_effect=[
            FakeScalarResult(None),
            FakeScalarResult([port()]),
            FakeScalarResult(86),
            FakeScalarResult(task("nuclei_safe", "completed", 200)),
            FakeScalarResult(task("dirb_safe", "completed", 201)),
            FakeScalarResult(None),
            FakeScalarResult(None),
        ]
    )
    session.add = MagicMock()
    session.flush = AsyncMock()

    completed = await finalize_target_if_idle(18, session=session)

    assert completed is True
    update_stmt = session.execute.await_args_list[-1].args[0]
    assert update_stmt.compile().params["status"] == "completed"


@pytest.mark.asyncio
async def test_pending_approval_prevents_completed_status():
    session = MagicMock()
    session.execute = AsyncMock(return_value=FakeScalarResult(300))

    completed = await finalize_target_if_idle(18, session=session)

    assert completed is False
    assert session.execute.await_count == 1


@pytest.mark.asyncio
async def test_max_round_still_allows_completion():
    session = MagicMock()
    session.get = AsyncMock(return_value=target(current_round=5, max_round=5))
    session.execute = AsyncMock(
        side_effect=[
            FakeScalarResult(None),
            FakeScalarResult(None),
            FakeScalarResult(None),
        ]
    )

    completed = await finalize_target_if_idle(18, session=session, stop_reason="max_round_reached")

    assert completed is True


@pytest.mark.asyncio
async def test_duplicate_nuclei_prevention_advances_to_dirb():
    session = session_for_get_next(
        execute_results=[
            task("nuclei_safe", "completed", 200),
            86,
            task("nuclei_safe", "completed", 200),
            None,
            None,
        ]
    )

    with patch("worker.auto_loop.async_session", return_value=FakeAsyncSessionContext(session)), patch(
        "worker.auto_loop.generate_tool_task", new_callable=AsyncMock
    ) as mock_generate:
        mock_generate.return_value = {
            "action": "tool_task_created",
            "tool_task_id": 102,
            "approval_required": True,
            "approval_status": "pending_approval",
        }

        result = await get_next_tool_task(
            18,
            17,
            {"recommended_tool": "nuclei_safe", "recommended_action": "continue", "decision_score_id": 57},
        )

    assert result["action"] == "tool_task_created"
    assert mock_generate.await_args.kwargs["decision_result"]["recommended_tool"] == "dirb_safe"
