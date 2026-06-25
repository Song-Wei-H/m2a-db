"""Poll pending tool_tasks and execute via tool_runner."""

from __future__ import annotations
from worker.remote_runner import run_remote_tool

import asyncio
import logging
from dataclasses import dataclass

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import async_session
from app.models import OpenPort, Target, ToolResult, ToolTask, ToolRegistry, CommandTemplate
from app.tool_task_constants import (
    EXECUTABLE_APPROVAL_STATUSES,
    FAILED,
    PENDING,
    REJECTED,
    RUNNING,
)
from app.tool_task_state import tool_task_status_values
from worker.parsers.nmap_parser import parse_nmap_output
from worker.tool_runner import TaskContext, run_tool
from worker.safety import validate_task_execution
from worker.analysis_pipeline import analyze_tool_result_and_generate_task
from worker.auto_loop import finalize_target_if_idle, increment_target_round
from worker.cve_matcher import match_cves_for_target

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TaskSnapshot:
    id: int
    target_id: int
    open_port_id: int | None
    decision_score_id: int | None
    tool_name: str
    approval_required: bool
    approval_status: str


async def fetch_pending_tasks(db: AsyncSession, limit: int = 10) -> list[ToolTask]:
    stmt = (
        select(ToolTask)
        .where(
            ToolTask.status == PENDING,
            ToolTask.approval_status.in_(EXECUTABLE_APPROVAL_STATUSES),
        )
        .order_by(ToolTask.priority.desc(), ToolTask.id)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def _claim_task(db: AsyncSession, task_id: int) -> bool:
    result = await db.execute(
        update(ToolTask)
        .where(
            ToolTask.id == task_id,
            ToolTask.status == PENDING,
            ToolTask.approval_status.in_(EXECUTABLE_APPROVAL_STATUSES),
        )
        .values(**tool_task_status_values(PENDING, RUNNING))
        .returning(ToolTask.id)
    )
    return result.scalar_one_or_none() is not None


async def _load_task_context(db: AsyncSession, task: ToolTask) -> TaskContext:
    target = await db.get(Target, task.target_id)
    if target is None:
        raise ValueError(f"target_id={task.target_id} not found")

    port_row: OpenPort | None = None
    if task.open_port_id:
        port_row = await db.get(OpenPort, task.open_port_id)

    return TaskContext(
        task_id=task.id,
        target_id=task.target_id,
        tool_name=task.tool_name,
        host=target.target,
        port=port_row.port if port_row else None,
        protocol=port_row.protocol if port_row else None,
        service=port_row.service if port_row else None,
        open_port_id=task.open_port_id,
        decision_score_id=task.decision_score_id,
    )


async def _persist_result(db: AsyncSession, ctx: TaskContext, outcome) -> int:
    from worker.learning_feedback import create_learning_feedback
    
    row = ToolResult(
        target_id=ctx.target_id,
        open_port_id=ctx.open_port_id,
        tool_task_id=ctx.task_id,
        tool_name=ctx.tool_name,
        command=outcome.command,
        raw_output=outcome.raw_output,
        parsed_output=outcome.parsed_result,
        success=outcome.success,
        evidence=outcome.error_message,
        risk_level=_infer_risk_level(ctx.tool_name, outcome),
    )
    db.add(row)
    await db.flush()

    if outcome.success and ctx.tool_name == "httpx_basic":
        try:
            await match_cves_for_target(
                db,
                target_id=ctx.target_id,
                open_port_id=ctx.open_port_id,
                parsed_output=outcome.parsed_result,
            )
        except Exception:
            logger.exception("Failed to match CVEs for tool_result_id=%s", row.id)
    
    # Create learning feedback record
    try:
        await create_learning_feedback(
            db,
            row,
            decision_id=ctx.decision_score_id,
            service=ctx.service,
            recommended_action="verify" if not outcome.success else None,
        )
    except Exception:
        # Log but don't fail the main execution flow
        logger.exception("Failed to create learning feedback for tool_result_id=%s", row.id)
    if outcome.success and ctx.tool_name == "nmap_service":
        ports = parse_nmap_output(outcome.raw_output)

        for item in ports:

            exists = await db.execute(
                select(OpenPort).where(
                    OpenPort.target_id == ctx.target_id,
                    OpenPort.port == item["port"],
                    OpenPort.protocol == item["protocol"],
                )
            )

            if exists.scalar_one_or_none():
                continue

            db.add(
                OpenPort(
                    target_id=ctx.target_id,
                    ip=ctx.host,
                    port=item["port"],
                    protocol=item["protocol"],
                    service=item["service"],
                    product=item["product"],
                    version=item["version"],
                    state=item["state"],
                )
            )

    await db.execute(
        update(ToolTask)
        .where(ToolTask.id == ctx.task_id)
        .values(**tool_task_status_values(RUNNING, outcome.status))
    )

    return row.id


def _infer_risk_level(tool_name: str, outcome) -> str | None:
    if not outcome.success:
        return None

    if tool_name == "nuclei_safe":
        count = outcome.parsed_result.get("finding_count", 0)
        if count > 0:
            return "medium"

    if tool_name == "httpx_basic":
        codes = outcome.parsed_result.get("status_codes") or []
        if any(c and c >= 500 for c in codes):
            return "low"

    return "info"


async def _reject_task(task_id: int, reason: str) -> None:
    async with async_session() as db, db.begin():
        await db.execute(
            update(ToolTask)
            .where(ToolTask.id == task_id)
            .values(**tool_task_status_values(PENDING, REJECTED, reject_reason=reason[:2000]))
        )
    logger.warning("tool_task_id=%s rejected: %s", task_id, reason)


async def _fail_task(
    snapshot: TaskSnapshot,
    reason: str,
    *,
    command: str | None = None,
) -> None:
    from worker.learning_feedback import create_learning_feedback
    
    async with async_session() as db, db.begin():
        await db.execute(
            update(ToolTask)
            .where(ToolTask.id == snapshot.id)
            .values(**tool_task_status_values(RUNNING, FAILED, reject_reason=reason[:2000]))
        )

        row = ToolResult(
            target_id=snapshot.target_id,
            open_port_id=snapshot.open_port_id,
            tool_task_id=snapshot.id,
            tool_name=snapshot.tool_name,
            command=command,
            raw_output=reason,
            parsed_output={"status": "failed", "error": reason},
            success=False,
            evidence=reason,
        )
        db.add(row)
        await db.flush()
        
        # Create learning feedback record
        try:
            await create_learning_feedback(
                db,
                row,
                decision_id=snapshot.decision_score_id,
                recommended_action="verify",
            )
        except Exception:
            # Log but don't fail the main execution flow
            logger.exception("Failed to create learning feedback for tool_result_id=%s", row.id)

    logger.error("tool_task_id=%s failed: %s", snapshot.id, reason)
    await finalize_target_if_idle(snapshot.target_id, stop_reason="task_failed")


async def execute_task(task_id: int) -> None:
    ctx: TaskContext | None = None
    template_row: CommandTemplate | None = None
    task_snapshot: TaskSnapshot | None = None

    async with async_session() as db, db.begin():
        if not await _claim_task(db, task_id):
            logger.debug("tool_task_id=%s already claimed or not executable", task_id)
            return

        task = await db.get(ToolTask, task_id)
        if task is None:
            logger.warning("tool_task_id=%s not found after claim", task_id)
            return

        task_snapshot = TaskSnapshot(
            id=task.id,
            target_id=task.target_id,
            open_port_id=task.open_port_id,
            decision_score_id=task.decision_score_id,
            tool_name=task.tool_name,
            approval_required=task.approval_required,
            approval_status=task.approval_status,
        )
        await db.execute(
            update(Target)
            .where(Target.id == task.target_id, Target.status == PENDING)
            .values(status=RUNNING)
        )

        reg_stmt = (
            select(ToolRegistry)
            .where(ToolRegistry.tool_name == task.tool_name)
            .limit(1)
        )
        reg_row = (await db.execute(reg_stmt)).scalar_one_or_none()
        if reg_row is None or not reg_row.enabled:
            await db.execute(
                update(ToolTask)
                .where(ToolTask.id == task.id)
                .values(
                    **tool_task_status_values(
                        RUNNING,
                        REJECTED,
                        reject_reason="Tool is not enabled in registry",
                    )
                )
            )
            logger.warning(
                "tool_task_id=%s rejected: Tool is not enabled in registry",
                task.id,
            )
            return

        try:
            ctx = await _load_task_context(db, task)
        except ValueError as exc:
            await db.execute(
                update(ToolTask)
                .where(ToolTask.id == task.id)
                .values(**tool_task_status_values(RUNNING, REJECTED, reject_reason=str(exc)[:2000]))
            )
            logger.warning("tool_task_id=%s rejected: %s", task.id, exc)
            return

        stmt = (
            select(CommandTemplate)
            .where(
                CommandTemplate.tool_name == ctx.tool_name,
                CommandTemplate.enabled.is_(True),
            )
            .limit(1)
        )
        template_row = (await db.execute(stmt)).scalar_one_or_none()

        if template_row is None:
            await db.execute(
                update(ToolTask)
                .where(ToolTask.id == task.id)
                .values(
                    **tool_task_status_values(
                        RUNNING,
                        REJECTED,
                        reject_reason="CommandTemplate not enabled",
                    )
                )
            )
            logger.warning(
                "tool_task_id=%s rejected: CommandTemplate not enabled",
                task.id,
            )
            return

    if ctx is None or template_row is None or task_snapshot is None:
        logger.error("tool_task_id=%s missing execution context", task_id)
        return

    try:
        validate_task_execution(
            ctx.tool_name,
            ctx.host,
            task_snapshot.approval_required,
            task_snapshot.approval_status,
        )

        logger.info(
            "tool_task_id=%s executing tool=%s host=%s approval_status=%s",
            task_id,
            ctx.tool_name,
            ctx.host,
            task_snapshot.approval_status,
        )

        outcome = await run_remote_tool(ctx)

    except ValueError as exc:
        logger.warning("tool_task_id=%s rejected: %s", task_id, exc)
        await _fail_task(task_snapshot, str(exc))
        return

    except TimeoutError as exc:
        reason = str(exc) or "remote tool timeout"
        logger.exception("tool_task_id=%s execution timeout: %s", task_id, reason)
        await _fail_task(task_snapshot, reason, command=f"remote:{ctx.tool_name}")
        return

    except Exception as exc:
        logger.exception("tool_task_id=%s execution error: %s", task_id, exc)
        await _fail_task(task_snapshot, "execution error")
        return

    async with async_session() as db, db.begin():
        result_id = await _persist_result(db, ctx, outcome)

    # Auto loop integration
    try:
        # Increment target round after successful task completion
        await increment_target_round(ctx.target_id)
        
        # Continue with normal analysis pipeline
        await analyze_tool_result_and_generate_task(
            target_id=ctx.target_id,
            open_port_id=ctx.open_port_id,
            tool_name=ctx.tool_name,
            parsed_output=outcome.parsed_result,
            raw_output=outcome.raw_output,
            tool_result_id=result_id,
            ctx=ctx,
            decision_score_id=ctx.decision_score_id,
        )
        await finalize_target_if_idle(ctx.target_id)
    except Exception as exc:
        logger.exception(
            "tool_task_id=%s analysis pipeline failed: %s",
            ctx.task_id,
            exc,
        )
        await finalize_target_if_idle(ctx.target_id, stop_reason="analysis_failed")

    logger.info(
        "tool_task_id=%s finished status=%s tool_result_id=%s",
        task_id,
        outcome.status,
        result_id,
    )


async def poll_once() -> int:
    async with async_session() as db, db.begin():
        tasks = await fetch_pending_tasks(db)

    for task in tasks:
        await execute_task(task.id)

    return len(tasks)


async def run_poller() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    logger.info(
        "Worker executor started (poll=%ss, timeout=%ss)",
        settings.worker_poll_interval_seconds,
        settings.worker_tool_timeout_seconds,
    )

    while True:
        try:
            count = await poll_once()
            if count:
                logger.info("Processed %s pending tool_task(s)", count)
        except Exception:
            logger.exception("Worker poll cycle failed")

        await asyncio.sleep(settings.worker_poll_interval_seconds)


def main() -> None:
    asyncio.run(run_poller())


if __name__ == "__main__":
    main()
