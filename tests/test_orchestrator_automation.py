from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from app.api.targets import create_target
from app.database import get_db
from app.main import app
from app.models import ToolTask
from app.schemas import TargetCreate
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


@pytest.mark.asyncio
async def test_post_targets_creates_initial_nmap_service_tool_task():
    db = MagicMock()
    added = []

    def add(row):
        added.append(row)

    async def flush():
        for row in added:
            if row.__class__.__name__ == "Target" and getattr(row, "id", None) is None:
                row.id = 101
            if row.__class__.__name__ == "ScanRun" and getattr(row, "id", None) is None:
                row.id = 201

    db.add.side_effect = add
    db.flush = AsyncMock(side_effect=flush)
    db.begin.return_value = FakeAsyncSessionContext(db)

    response = await create_target(
        TargetCreate(target="198.51.100.10", target_type="ip", scope="internal"),
        db,
    )

    task = next(row for row in added if isinstance(row, ToolTask))
    assert response.target_id == 101
    assert response.scan_run_id == 201
    assert response.status == "pending"
    assert task.target_id == 101
    assert task.tool_name == "nmap_service"
    assert task.status == "pending"
    assert task.approval_required is False
    assert task.approval_status == "not_required"
    assert not hasattr(task, "command")


def test_run_status_endpoint_returns_task_counts_and_report_ready():
    client = TestClient(app)
    target = SimpleNamespace(
        id=7,
        target="198.51.100.10",
        status="completed",
        current_round=3,
        max_round=5,
    )
    decision = SimpleNamespace(
        id=44,
        risk_score=4.0,
        severity="medium",
        next_action="stop",
        next_tool=None,
        reason="No next tool selected",
        created_at=None,
    )
    fake_db = MagicMock()
    fake_db.get = AsyncMock(return_value=target)
    fake_db.scalar = AsyncMock(side_effect=[0, 0, 2, 0])
    fake_db.execute = AsyncMock(return_value=FakeScalarResult(decision))

    async def override_get_db():
        yield fake_db

    app.dependency_overrides[get_db] = override_get_db
    try:
        response = client.get("/targets/7/run-status")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["target_id"] == 7
    assert body["target"] == "198.51.100.10"
    assert body["status"] == "completed"
    assert body["current_round"] == 3
    assert body["max_rounds"] == 5
    assert body["pending_task_count"] == 0
    assert body["completed_task_count"] == 2
    assert body["latest_next_action"] == "stop"
    assert body["latest_next_tool"] is None
    assert body["report_ready"] is True
    assert body["latest_decision"]["decision_score_id"] == 44


def test_run_status_endpoint_returns_404_for_missing_target():
    client = TestClient(app)
    fake_db = MagicMock()
    fake_db.get = AsyncMock(return_value=None)

    async def override_get_db():
        yield fake_db

    app.dependency_overrides[get_db] = override_get_db
    try:
        response = client.get("/targets/404/run-status")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 404
    assert response.json() == {"detail": "Target not found"}


@pytest.mark.asyncio
async def test_next_action_stop_completes_target_without_creating_task():
    target = SimpleNamespace(id=7, status="running", current_round=2, max_round=5)
    session = MagicMock()
    session.get = AsyncMock(return_value=target)
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.begin.return_value = FakeAsyncSessionContext(session)
    session.execute = AsyncMock(
        side_effect=[
            FakeScalarResult(None),
            FakeScalarResult([]),
            FakeScalarResult(None),
            FakeScalarResult(None),
        ]
    )

    from unittest.mock import patch

    with patch("worker.auto_loop.async_session", return_value=FakeAsyncSessionContext(session)), patch(
        "worker.auto_loop.generate_tool_task",
        AsyncMock(),
    ) as mock_generate:
        result = await get_next_tool_task(
            7,
            None,
            {
                "recommended_action": "stop",
                "recommended_tool": None,
                "decision_score_id": 44,
            },
        )

    assert result["action"] == "stop"
    assert result["target_completed"] is True
    mock_generate.assert_not_awaited()
    update_stmt = session.execute.await_args_list[-1].args[0]
    assert update_stmt.compile().params["status"] == "completed"
