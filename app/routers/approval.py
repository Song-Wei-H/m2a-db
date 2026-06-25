from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import UTC, datetime
from pydantic import BaseModel

from app.database import get_db
from app.models import ToolTask
from app.tool_task_constants import APPROVAL_REJECTED, APPROVED, PENDING, PENDING_APPROVAL
from app.tool_task_state import validate_approval_transition

router = APIRouter(tags=["approvals"])


class ApprovalRequest(BaseModel):
    approved_by: str = "human"
    reason: str | None = None


@router.get("/approvals/pending", response_model=list[int])
async def get_pending_approvals(
    db: AsyncSession = Depends(get_db),
):
    """Return list of tool_task IDs pending approval."""
    result = await db.execute(
        select(ToolTask.id).where(
            ToolTask.status == PENDING,
            ToolTask.approval_required == True,
            ToolTask.approval_status == PENDING_APPROVAL,
        )
    )

    ids = [row[0] for row in result.fetchall()]
    return ids


@router.post("/approvals/{task_id}/approve")
async def approve_task(
    task_id: int,
    body: ApprovalRequest | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Approve a pending task."""
    result = await db.execute(
        select(ToolTask).where(ToolTask.id == task_id)
    )

    task: ToolTask | None = result.scalar_one_or_none()

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if task.approval_status != PENDING_APPROVAL:
        raise HTTPException(
            status_code=400,
            detail="Task not pending approval",
        )

    validate_approval_transition(task.approval_status, APPROVED)
    task.approval_status = APPROVED
    task.approved_at = datetime.now(UTC)
    task.approved_by = body.approved_by if body else "human"

    await db.commit()

    return {
        "status": APPROVED,
        "task_id": task_id,
    }


@router.post("/approvals/{task_id}/reject")
async def reject_task(
    task_id: int,
    body: ApprovalRequest | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Reject a pending task."""
    result = await db.execute(
        select(ToolTask).where(ToolTask.id == task_id)
    )

    task: ToolTask | None = result.scalar_one_or_none()

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if task.approval_status != PENDING_APPROVAL:
        raise HTTPException(
            status_code=400,
            detail="Task not pending approval",
        )

    validate_approval_transition(task.approval_status, APPROVAL_REJECTED)
    task.approval_status = APPROVAL_REJECTED
    task.approved_at = datetime.now(UTC)
    task.approved_by = body.approved_by if body else "human"
    task.reject_reason = (
        body.reason
        if body and body.reason
        else "Rejected by human"
    )

    await db.commit()

    return {
        "status": APPROVAL_REJECTED,
        "task_id": task_id,
    }
