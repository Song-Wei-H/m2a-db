from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.decision_engine import run_decision_for_target
from app.schemas import DecisionRunResponse

router = APIRouter(tags=["decisions"])


@router.post(
    "/decisions/run/{target_id}",
    response_model=DecisionRunResponse,
)
async def run_decision(
    target_id: int,
    db: AsyncSession = Depends(get_db),
) -> DecisionRunResponse:
    result = await run_decision_for_target(db, target_id)
    return DecisionRunResponse(
        target_id=result.target_id,
        next_action=result.next_action,
        next_tool=result.next_tool,
        mitre_phase=result.mitre_phase,
        mitre_technique=result.mitre_technique,
        risk_score=result.risk_score,
        confidence=result.confidence,
        reason=result.reason,
    )
