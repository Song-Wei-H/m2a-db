from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import OpenPort, Target
from app.schemas import OpenPortResponse

router = APIRouter(tags=["open-ports"])


@router.get(
    "/targets/{target_id}/open-ports",
    response_model=list[OpenPortResponse],
)
async def list_target_open_ports(
    target_id: int,
    db: AsyncSession = Depends(get_db),
) -> list[OpenPort]:
    target = await db.get(Target, target_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"target_id={target_id} not found",
        )

    result = await db.execute(
        select(OpenPort)
        .where(OpenPort.target_id == target_id)
        .order_by(OpenPort.port, OpenPort.protocol)
    )
    return list(result.scalars().all())
