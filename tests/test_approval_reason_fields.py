from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.routers.approval import ApprovalRequest, reject_task


class FakeScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


@pytest.mark.asyncio
async def test_reject_task_writes_reject_reason_not_approval_reason():
    task = SimpleNamespace(
        id=10,
        approval_status="pending_approval",
        approval_reason="High-risk validation requires human approval",
        reject_reason=None,
        approved_at=None,
        approved_by=None,
    )
    db = AsyncMock()
    db.execute = AsyncMock(return_value=FakeScalarResult(task))
    db.commit = AsyncMock()

    response = await reject_task(10, ApprovalRequest(approved_by="analyst", reason="Out of scope"), db)

    assert response == {"status": "rejected", "task_id": 10}
    assert task.approval_reason == "High-risk validation requires human approval"
    assert task.reject_reason == "Out of scope"
    assert task.approved_by == "analyst"
