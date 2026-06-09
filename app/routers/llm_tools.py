"""API for validated LLM tool proposals (JSON only, no shell)."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.security.llm_schema import RiskLevel
from app.tool_task_dispatcher import dispatch_llm_tool_proposal

router = APIRouter(tags=["llm-tools"])


class LlmToolProposalRequest(BaseModel):
    """Same contract as LLM output; rejects command/shell fields."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    target: str
    reason: str
    risk_level: RiskLevel
    profile: str = Field(default="internal", description="Must match ALLOWED_LLM_PROFILES")
    target_id: int | None = None
    open_port_id: int | None = None


class LlmToolProposalResponse(BaseModel):
    accepted: bool
    tool_task_id: int | None
    status: str
    message: str
    tool: str | None = None
    target: str | None = None
    risk_level: str | None = None


@router.post("/tools/llm-propose", response_model=LlmToolProposalResponse)
async def propose_llm_tool(
    body: LlmToolProposalRequest,
    db: AsyncSession = Depends(get_db),
) -> LlmToolProposalResponse:
    """
    Dispatcher validates LLM JSON and enqueues tool_tasks.
    LLM must never pass shell commands — only this schema is accepted.
    """
    async with db.begin():
        result = await dispatch_llm_tool_proposal(
            db,
            body.model_dump(exclude={"profile", "target_id", "open_port_id"}),
            profile=body.profile,
            target_id=body.target_id,
            open_port_id=body.open_port_id,
        )

    proposal = result.proposal
    return LlmToolProposalResponse(
        accepted=result.accepted,
        tool_task_id=result.tool_task_id,
        status=result.status,
        message=result.message,
        tool=proposal.tool if proposal else None,
        target=proposal.target if proposal else None,
        risk_level=proposal.risk_level if proposal else None,
    )
