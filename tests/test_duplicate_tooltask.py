from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models import ToolTask
from app.tool_task_writer import create_tool_task_if_not_exists, find_active_tool_task


class FakeScalarResult:
    def __init__(self, value=None):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


@pytest.mark.asyncio
async def test_find_active_tool_task_matches_null_open_port():
    existing = ToolTask(id=1, target_id=7, open_port_id=None, tool_name="nmap_service", status="pending")
    session = MagicMock()
    session.execute = AsyncMock(return_value=FakeScalarResult(existing))

    found = await find_active_tool_task(
        session,
        target_id=7,
        open_port_id=None,
        tool_name="nmap_service",
    )

    assert found is existing


@pytest.mark.asyncio
async def test_create_tool_task_returns_existing_when_insert_conflicts():
    existing = ToolTask(id=44, target_id=7, open_port_id=3, tool_name="httpx_basic", status="pending")
    session = MagicMock()
    session.execute = AsyncMock(side_effect=[FakeScalarResult(None), FakeScalarResult(existing)])
    session.get = AsyncMock(return_value=None)

    task, inserted = await create_tool_task_if_not_exists(
        session,
        target_id=7,
        open_port_id=3,
        tool_name="httpx_basic",
        status="pending",
        priority=50,
    )

    assert inserted is False
    assert task is existing


@pytest.mark.asyncio
async def test_create_tool_task_reports_inserted_when_insert_returns_id():
    inserted = ToolTask(id=45, target_id=7, open_port_id=3, tool_name="httpx_basic", status="pending")
    session = MagicMock()
    session.execute = AsyncMock(return_value=FakeScalarResult(45))
    session.get = AsyncMock(return_value=inserted)

    task, was_inserted = await create_tool_task_if_not_exists(
        session,
        target_id=7,
        open_port_id=3,
        tool_name="httpx_basic",
        status="pending",
        priority=50,
    )

    assert was_inserted is True
    assert task is inserted
