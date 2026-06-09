from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import ScanRun, Target
from app.schemas import TargetCreate, TargetCreateResponse

router = APIRouter(tags=["targets"])


@router.post(
    "/targets",
    response_model=TargetCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_target(
    body: TargetCreate,
    db: AsyncSession = Depends(get_db),
) -> TargetCreateResponse:
    target = Target(
        target=body.target,
        target_type=body.target_type,
        scope=body.scope,
        status="pending",
    )
    scan_run = ScanRun(
        round=1,
        scan_type="nmap",
        status="pending",
    )

    # targets + scan_runs must commit together; otherwise dispatcher has nothing to pick up.
    async with db.begin():
        db.add(target)
        await db.flush()
        scan_run.target_id = target.id
        db.add(scan_run)
        await db.flush()

    if scan_run.id is None or target.id is None:
        raise RuntimeError("POST /targets failed to create target and scan_run in one transaction")

    return TargetCreateResponse(        target_id=target.id,
        scan_run_id=scan_run.id,
        status=scan_run.status,
    )
