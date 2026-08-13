from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import UTC, datetime
from pydantic import BaseModel, Field, field_validator

from app.database import get_db
from app.models import Target, ToolTask
from app.tool_task_constants import APPROVAL_REJECTED, APPROVED, PENDING, PENDING_APPROVAL
from app.tool_task_state import validate_approval_transition

router = APIRouter(tags=["approvals"])


class ApprovalRequest(BaseModel):
    approved_by: str = "human"
    reason: str = Field(min_length=1, max_length=2000)

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("reason must not be blank")
        return value


class PendingApproval(BaseModel):
    task_id: int
    target_id: int
    target: str
    scope: str | None = None
    tool_name: str
    proposal_reason: str | None = None
    approval_reason: str | None = None
    created_at: datetime


@router.get("/approvals/pending", response_model=list[PendingApproval])
async def get_pending_approvals(
    db: AsyncSession = Depends(get_db),
):
    """Return enough immutable task context for an informed human decision."""
    result = await db.execute(
        select(ToolTask, Target).join(Target, Target.id == ToolTask.target_id).where(
            ToolTask.status == PENDING,
            ToolTask.approval_required == True,
            ToolTask.approval_status == PENDING_APPROVAL,
        )
    )

    return [
        PendingApproval(
            task_id=task.id,
            target_id=task.target_id,
            target=target.target,
            scope=target.scope,
            tool_name=task.tool_name,
            proposal_reason=task.proposal_reason,
            approval_reason=task.approval_reason,
            created_at=task.created_at,
        )
        for task, target in result.fetchall()
    ]


@router.post("/approvals/{task_id}/approve")
async def approve_task(
    task_id: int,
    body: ApprovalRequest,
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
    task.approved_by = body.approved_by
    task.approval_decision_reason = body.reason

    await db.commit()

    return {
        "status": APPROVED,
        "task_id": task_id,
    }


@router.post("/approvals/{task_id}/reject")
async def reject_task(
    task_id: int,
    body: ApprovalRequest,
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
    task.approved_by = body.approved_by
    task.approval_decision_reason = body.reason
    task.reject_reason = (
        body.reason
    )

    await db.commit()

    return {
        "status": APPROVAL_REJECTED,
        "task_id": task_id,
    }
