"""Poll pending tool_tasks and dispatch allowed jobs to Kali Worker /execute."""

from __future__ import annotations
from worker.analysis_pipeline import analyze_tool_result_and_generate_task
from worker.tool_runner import _parse_output
import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import async_session
from app.models import Target, ToolResult, ToolTask

logger = logging.getLogger(__name__)

EXECUTE_PATH = "/execute"

VALID_READY_APPROVAL = {"not_required", "approved"}
FINAL_STATUSES = {"completed", "failed", "rejected"}


@dataclass(frozen=True)
class PendingToolJob:
    task_id: int
    target_id: int
    target: str
    tool_name: str
    open_port_id: int | None = None
    port: int | None = None


def _extract_output(payload: dict[str, Any]) -> str:
    return (
        payload.get("raw_output")
        or payload.get("output")
        or payload.get("stdout")
        or payload.get("error")
        or payload.get("reason")
        or str(payload)
    )


async def _recover_stale_running(db: AsyncSession) -> int:
    cutoff = datetime.now() - timedelta(
        minutes=settings.dispatcher_stale_running_minutes
    )

    result = await db.execute(
        update(ToolTask)
        .where(
            ToolTask.status == "running",
            ToolTask.created_at < cutoff,
        )
        .values(status="pending")
        .returning(ToolTask.id)
    )

    recovered = result.scalars().all()

    for task_id in recovered:
        logger.warning("Recovered stale running tool_task_id=%s", task_id)

    return len(recovered)


async def _fetch_pending_jobs(db: AsyncSession) -> list[PendingToolJob]:
    stmt = (
        select(
            ToolTask.id,
            ToolTask.target_id,
            Target.target,
            ToolTask.tool_name,
            ToolTask.open_port_id,
        )
        .join(Target, Target.id == ToolTask.target_id)
        .where(
            ToolTask.status == "pending",
            ToolTask.approval_status.in_(VALID_READY_APPROVAL),
        )
        .order_by(ToolTask.id)
        .with_for_update(skip_locked=True)
    )

    result = await db.execute(stmt)
    rows = result.all()

    return [
        PendingToolJob(
            task_id=task_id,
            target_id=target_id,
            target=target,
            tool_name=tool_name,
            open_port_id=open_port_id,
            port=None,
        )
        for task_id, target_id, target, tool_name, open_port_id in rows
        if target_id is not None and target is not None and tool_name is not None
    ]


async def _claim_jobs(db: AsyncSession) -> list[PendingToolJob]:
    await _recover_stale_running(db)

    jobs = await _fetch_pending_jobs(db)
    if not jobs:
        return []

    for job in jobs:
        await db.execute(
            update(ToolTask)
            .where(
                ToolTask.id == job.task_id,
                ToolTask.status == "pending",
            )
            .values(status="running")
        )

    return jobs


async def _call_kali_worker(
    client: httpx.AsyncClient,
    job: PendingToolJob,
) -> dict[str, Any]:
    url = f"{settings.kali_worker_url.rstrip('/')}{EXECUTE_PATH}"

    payload = {
        "tool": job.tool_name,
        "target": job.target,
        "port": job.port,
    }

    response = await client.post(url, json=payload)
    response.raise_for_status()

    return response.json()


async def _write_tool_result(
    db: AsyncSession,
    job: PendingToolJob,
    payload: dict[str, Any],
) -> bool:
    worker_status = payload.get("status")
    success = worker_status == "completed"

    raw_output = _extract_output(payload)
    parsed_output = _parse_output(job.tool_name, raw_output, success)

    result = ToolResult(
        target_id=job.target_id,
        open_port_id=job.open_port_id,
        tool_task_id=job.task_id,
        tool_name=job.tool_name,
        command=payload.get("command"),
        raw_output=raw_output,
        parsed_output=parsed_output,
        success=success,
        evidence=payload.get("error") or payload.get("reason"),
    )

    db.add(result)
    await db.flush()

    # Create learning feedback record
    try:
        from worker.learning_feedback import create_learning_feedback
        await create_learning_feedback(db, result)
    except Exception:
        # Log but don't fail the main execution flow
        logger.exception("Failed to create learning feedback for tool_result_id=%s", result.id)

    if success:
        await analyze_tool_result_and_generate_task(
            target_id=job.target_id,
            open_port_id=job.open_port_id,
            tool_name=job.tool_name,
            parsed_output=parsed_output,
            raw_output=raw_output,
            tool_result_id=result.id,
            decision_score_id=None,
        )

    new_status = "completed" if success else "failed"

    if worker_status == "rejected":
        new_status = "rejected"

    await db.execute(
        update(ToolTask)
        .where(ToolTask.id == job.task_id)
        .values(status=new_status)
    )

    return success


async def _mark_failed(task_id: int, reason: str) -> None:
    async with async_session() as db, db.begin():
        await db.execute(
            update(ToolTask)
            .where(ToolTask.id == task_id)
            .values(status="failed")
        )

        result = ToolResult(
            tool_task_id=task_id,
            success=False,
            raw_output=reason,
            evidence=reason,
        )

        db.add(result)

        # Create learning feedback record
        try:
            from worker.learning_feedback import create_learning_feedback
            await create_learning_feedback(db, result)
        except Exception:
            # Log but don't fail the main execution flow
            logger.exception("Failed to create learning feedback for tool_result_id=%s", result.id)

    logger.error("tool_task_id=%s failed: %s", task_id, reason)


async def _process_job(
    client: httpx.AsyncClient,
    job: PendingToolJob,
) -> None:
    logger.info(
        "Dispatching tool_task_id=%s tool=%s target=%s",
        job.task_id,
        job.tool_name,
        job.target,
    )

    try:
        payload = await _call_kali_worker(client, job)
    except Exception as exc:
        logger.exception("Kali Worker call failed for tool_task_id=%s", job.task_id)
        await _mark_failed(job.task_id, f"Kali Worker error: {exc}")
        return

    try:
        async with async_session() as db, db.begin():
            worker_status = payload.get("status")
            success = worker_status == "completed"
            raw_output = _extract_output(payload)
            parsed_output = _parse_output(job.tool_name, raw_output, success)
            
            result = ToolResult(
                target_id=job.target_id,
                open_port_id=job.open_port_id,
                tool_task_id=job.task_id,
                tool_name=job.tool_name,
                command=payload.get("command"),
                raw_output=raw_output,
                parsed_output=parsed_output,
                success=success,
                evidence=payload.get("error") or payload.get("reason"),
            )

            db.add(result)
            await db.flush()

            tool_result_id = result.id

            # Create learning feedback record
            try:
                from worker.learning_feedback import create_learning_feedback
                await create_learning_feedback(db, result)
            except Exception:
                # Log but don't fail the main execution flow
                logger.exception("Failed to create learning feedback for tool_result_id=%s", result.id)

            new_status = "completed" if success else "failed"

            if worker_status == "rejected":
                new_status = "rejected"

            await db.execute(
                update(ToolTask)
                .where(ToolTask.id == job.task_id)
                .values(status=new_status)
            )

    except Exception as exc:
        logger.exception("DB write failed for tool_task_id=%s", job.task_id)
        await _mark_failed(job.task_id, f"DB write error: {exc}")
        return

    if success:
        try:
            await analyze_tool_result_and_generate_task(
                target_id=job.target_id,
                open_port_id=job.open_port_id,
                tool_name=job.tool_name,
                parsed_output=parsed_output,
                raw_output=raw_output,
                tool_result_id=tool_result_id,
                decision_score_id=None,
            )
        except Exception as exc:
            logger.exception(
                "Analysis pipeline failed for tool_task_id=%s tool_result_id=%s",
                job.task_id,
                tool_result_id,
            )
            return

    logger.info(
        "Finished tool_task_id=%s success=%s",
        job.task_id,
        success,
    )


async def poll_once(client: httpx.AsyncClient) -> int:
    async with async_session() as db, db.begin():
        jobs = await _claim_jobs(db)

    if not jobs:
        return 0

    for job in jobs:
        await _process_job(client, job)

    return len(jobs)


async def run_dispatcher() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    logger.info(
        "ToolTask Dispatcher started poll=%ss worker=%s stale_running=%s min",
        settings.dispatcher_poll_interval_seconds,
        settings.kali_worker_url,
        settings.dispatcher_stale_running_minutes,
    )

    timeout = httpx.Timeout(settings.kali_worker_timeout_seconds)

    async with httpx.AsyncClient(timeout=timeout) as client:
        while True:
            try:
                count = await poll_once(client)
                if count:
                    logger.info("Processed %s pending tool_task(s)", count)
            except Exception:
                logger.exception("Dispatcher poll cycle failed")

            await asyncio.sleep(settings.dispatcher_poll_interval_seconds)


def main() -> None:
    asyncio.run(run_dispatcher())


if __name__ == "__main__":
    main()