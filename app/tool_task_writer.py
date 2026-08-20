from __future__ import annotations

from typing import Any

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ToolTask
from app.action_contracts import ACTION_BY_TOOL
from app.tool_task_constants import ACTIVE_TASK_STATUSES


async def find_active_tool_task(
    session: AsyncSession,
    *,
    target_id: int,
    open_port_id: int | None,
    tool_name: str,
) -> ToolTask | None:
    query = (
        select(ToolTask)
        .where(
            ToolTask.target_id == target_id,
            ToolTask.tool_name == tool_name,
            ToolTask.status.in_(ACTIVE_TASK_STATUSES),
        )
        .order_by(ToolTask.id.desc())
        .limit(1)
    )
    if open_port_id is None:
        query = query.where(ToolTask.open_port_id.is_(None))
    else:
        query = query.where(ToolTask.open_port_id == open_port_id)
    return (await session.execute(query)).scalar_one_or_none()


async def create_tool_task_if_not_exists(
    session: AsyncSession,
    **values: Any,
) -> tuple[ToolTask | None, bool]:
    await _adapt_migrated_action(session, values)
    target_id = values["target_id"]
    open_port_id = values.get("open_port_id")
    tool_name = values["tool_name"]

    stmt = (
        pg_insert(ToolTask)
        .values(**values)
        .on_conflict_do_nothing(
            index_elements=[
                ToolTask.target_id,
                text("COALESCE(open_port_id, -1)"),
                ToolTask.tool_name,
            ],
            index_where=ToolTask.status.in_(ACTIVE_TASK_STATUSES),
        )
        .returning(ToolTask.id)
    )
    try:
        # PostgreSQL can reject ON CONFLICT when an older database is missing
        # the matching partial expression index. Isolate that compatibility
        # failure in a savepoint so the caller's outer transaction remains
        # usable for the deterministic fallback below.
        async with session.begin_nested():
            inserted_id = (await session.execute(stmt)).scalar_one_or_none()
    except TypeError:
        task = ToolTask(**values)
        session.add(task)
        await session.flush()
        return task, True
    except SQLAlchemyError:
        existing = await find_active_tool_task(
            session,
            target_id=target_id,
            open_port_id=open_port_id,
            tool_name=tool_name,
        )
        if existing is not None:
            return existing, False
        task = ToolTask(**values)
        session.add(task)
        await session.flush()
        return task, True

    if inserted_id is not None:
        task = await session.get(ToolTask, inserted_id)
        if task is not None:
            return task, True

    existing = await find_active_tool_task(
        session,
        target_id=target_id,
        open_port_id=open_port_id,
        tool_name=tool_name,
    )
    if existing is not None:
        return existing, False

    task = ToolTask(**values)
    session.add(task)
    await session.flush()
    return task, True


async def _adapt_migrated_action(session: AsyncSession, values: dict[str, Any]) -> None:
    target_id = values["target_id"]
    open_port_id = values.get("open_port_id")
    tool_name = values["tool_name"]
    if tool_name in ACTION_BY_TOOL and values.get("status") != "rejected":
        if (not values.get("execution_authorization_id")
                or values.get("action_id") != ACTION_BY_TOOL[tool_name]
                or not values.get("investigation_id")):
            from app.execution_governance import canonical_parameters, propose_and_authorize
            from app.models import OpenPort, Target
            target = await session.get(Target, target_id)
            port_row = await session.get(OpenPort, open_port_id) if open_port_id else None
            if target is None:
                raise ValueError(f"target_id={target_id} not found")
            action_id = ACTION_BY_TOOL[tool_name]
            governed = await propose_and_authorize(
                session, target=target, tool_name=tool_name,
                parameters=canonical_parameters(
                    target=target.target, port=port_row.port if port_row else None,
                    protocol=port_row.protocol if port_row else None,
                    service=port_row.service if port_row else None, action_id=action_id,
                ),
                reason=str(values.get("proposal_reason") or values.get("approval_reason")
                           or "Legacy creation path adapted by canonical ToolTask writer"),
                confidence=None, provider="legacy-governance-adapter",
                authorization_source="gade-tier-policy",
            )
            if governed.authorization is None:
                raise ValueError(f"Human authorization required for {action_id}")
            values.update(investigation_id=governed.proposal.investigation_id,
                          action_id=governed.action.action_id,
                          execution_authorization_id=governed.authorization.id,
                          approval_required=False, approval_status="not_required")


async def create_retest_tool_task(
    session: AsyncSession,
    **values: Any,
) -> ToolTask:
    """Create an explicitly human-requested new-round task.

    Retests intentionally coexist with completed historical tasks. Callers
    must enforce completed-target state and preserve the human reason.
    """
    if not str(values.get("proposal_reason") or "").strip():
        raise ValueError("retest proposal_reason is required")
    await _adapt_migrated_action(session, values)
    task = ToolTask(**values)
    session.add(task)
    await session.flush()
    return task
