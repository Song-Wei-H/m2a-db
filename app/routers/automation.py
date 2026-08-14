"""Target-scoped automation with a fixed governed execution entry point."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.database import async_session
from app.models import ScanRun, Target
from app.tool_task_constants import NOT_REQUIRED, PENDING
from app.tool_task_writer import create_retest_tool_task
from app.routers.worker_preflight import worker_preflight
from worker.task_poller import run_target_automation

router = APIRouter(prefix="/automation", tags=["automation"])
_target_tasks: dict[int, asyncio.Task[None]] = {}
_start_lock = asyncio.Lock()


class RetestRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=1000)


def _running(target_id: int) -> bool:
    task = _target_tasks.get(target_id)
    return task is not None and not task.done()


@router.get("/targets/{target_id}/status")
async def automation_status(target_id: int) -> dict:
    return {"target_id": target_id, "status": "running" if _running(target_id) else "stopped"}


@router.post("/targets/{target_id}/start")
async def start_target_automation(target_id: int) -> dict:
    """Start only one existing target; no command or tool input is accepted."""
    async with _start_lock:
        if _running(target_id):
            return {"target_id": target_id, "status": "already_running"}
        async with async_session() as db:
            if await db.get(Target, target_id) is None:
                raise HTTPException(status_code=404, detail="target not found")
        preflight = await worker_preflight()
        if preflight.get("status") != "READY":
            raise HTTPException(status_code=503, detail={"reason": "worker_preflight_not_ready", "preflight": preflight})
        _target_tasks[target_id] = asyncio.create_task(
            run_target_automation(target_id), name=f"m2a-target-{target_id}"
        )
        return {"target_id": target_id, "status": "started", "preflight": "READY"}


@router.post("/targets/{target_id}/retest")
async def retest_target(target_id: int, body: RetestRequest) -> dict:
    """Create a new audited nmap round for one completed target and run it."""
    async with _start_lock:
        if _running(target_id):
            return {"target_id": target_id, "status": "already_running"}
        preflight = await worker_preflight()
        if preflight.get("status") != "READY":
            raise HTTPException(status_code=503, detail={"reason": "worker_preflight_not_ready", "preflight": preflight})
        async with async_session() as db, db.begin():
            target = await db.get(Target, target_id)
            if target is None:
                raise HTTPException(status_code=404, detail="target not found")
            if target.status != "completed":
                raise HTTPException(status_code=409, detail="retest requires a completed target")
            target.status = PENDING
            target.current_round = 1
            db.add(ScanRun(target_id=target_id, round=1, scan_type="retest", status=PENDING))
            task = await create_retest_tool_task(
                db,
                target_id=target_id, open_port_id=None, tool_name="nmap_service",
                status=PENDING, priority=50, approval_required=False,
                approval_status=NOT_REQUIRED,
                proposal_reason=f"Human-requested retest: {body.reason.strip()}",
            )
        _target_tasks[target_id] = asyncio.create_task(
            run_target_automation(target_id), name=f"m2a-target-{target_id}-retest"
        )
        return {"target_id": target_id, "status": "retest_started", "tool_task_id": task.id, "preflight": "READY"}
