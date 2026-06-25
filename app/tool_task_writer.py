from __future__ import annotations

from typing import Any

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ToolTask
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
