from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from app.routers.approval import ApprovalRequest, approve_task, get_pending_approvals, reject_task


def test_approval_request_rejects_blank_reason():
    with pytest.raises(ValidationError):
        ApprovalRequest(reason="   ")


class FakeScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


@pytest.mark.asyncio
async def test_reject_task_writes_reject_reason_not_approval_reason():
    task = SimpleNamespace(
        id=10,
        status="pending",
        approval_status="pending_approval",
        approval_reason="High-risk validation requires human approval",
        reject_reason=None,
        approved_at=None,
        approved_by=None,
        approval_decision_reason=None,
    )
    db = AsyncMock()
    db.execute = AsyncMock(return_value=FakeScalarResult(task))
    db.commit = AsyncMock()

    response = await reject_task(10, ApprovalRequest(approved_by="analyst", reason="Out of scope"), db)

    assert response == {"status": "rejected", "task_id": 10}
    assert task.approval_reason == "High-risk validation requires human approval"
    assert task.status == "rejected"
    assert task.reject_reason == "Out of scope"
    assert task.approved_by == "analyst"
    assert task.approval_decision_reason == "Out of scope"
    assert task.approved_at.tzinfo is None


@pytest.mark.asyncio
async def test_approve_task_preserves_human_decision_reason():
    task = SimpleNamespace(
        id=11,
        approval_status="pending_approval",
        approval_reason="High-risk validation requires human approval",
        approval_decision_reason=None,
        approved_at=None,
        approved_by=None,
    )
    db = AsyncMock()
    db.execute = AsyncMock(return_value=FakeScalarResult(task))
    db.commit = AsyncMock()

    response = await approve_task(
        11,
        ApprovalRequest(approved_by="lead", reason="Authorized exercise window"),
        db,
    )

    assert response == {"status": "approved", "task_id": 11}
    assert task.approval_reason == "High-risk validation requires human approval"
    assert task.approval_decision_reason == "Authorized exercise window"
    assert task.approved_by == "lead"
    assert task.approved_at.tzinfo is None


class FakeRowsResult:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return self.rows


@pytest.mark.asyncio
async def test_pending_approvals_include_decision_context():
    task = SimpleNamespace(
        id=12,
        target_id=4,
        tool_name="nuclei_safe",
        proposal_reason="Validate the observed service safely",
        approval_reason="High-risk validation requires human approval",
        created_at=__import__("datetime").datetime(2026, 8, 13, 12, 0, 0),
    )
    target = SimpleNamespace(target="192.0.2.25", scope="internal")
    db = AsyncMock()
    db.execute = AsyncMock(return_value=FakeRowsResult([(task, target)]))

    response = await get_pending_approvals(db)

    assert response[0].model_dump() == {
        "task_id": 12,
        "target_id": 4,
        "target": "192.0.2.25",
        "scope": "internal",
        "tool_name": "nuclei_safe",
        "proposal_reason": "Validate the observed service safely",
        "approval_reason": "High-risk validation requires human approval",
        "created_at": __import__("datetime").datetime(2026, 8, 13, 12, 0, 0),
    }
