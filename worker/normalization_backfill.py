"""Idempotent evidence backfill for historical successful nmap ToolResults.

This module never executes tools or changes raw results.  It only restores a
missing NormalizedResult from the original, traceable ToolResult payload.
"""

from __future__ import annotations

from types import SimpleNamespace

from sqlalchemy import select

from app.database import async_session
from app.models import NormalizedResult, Target, ToolResult
from worker.evidence_normalizer import normalize_tool_result


async def backfill_nmap_normalized_results(target_id: int) -> int:
    """Create missing normalized nmap evidence for one target, once per result."""
    created = 0
    async with async_session() as session, session.begin():
        target = await session.get(Target, target_id)
        if target is None:
            return 0

        tool_results = list(
            (
                await session.execute(
                    select(ToolResult).where(
                        ToolResult.target_id == target_id,
                        ToolResult.tool_name == "nmap_service",
                        ToolResult.success.is_(True),
                    )
                )
            )
            .scalars()
            .all()
        )
        for tool_result in tool_results:
            exists = await session.scalar(
                select(NormalizedResult.id)
                .where(NormalizedResult.tool_result_id == tool_result.id)
                .limit(1)
            )
            if exists is not None:
                continue

            evidence_list = normalize_tool_result(
                "nmap_service",
                tool_result.parsed_output or {},
                raw_output=tool_result.raw_output or "",
                ctx=SimpleNamespace(host=target.target),
                tool_result_id=tool_result.id,
            )
            for evidence in evidence_list:
                session.add(
                    NormalizedResult(
                        target_id=target_id,
                        open_port_id=tool_result.open_port_id,
                        tool_result_id=tool_result.id,
                        tool_name="nmap_service",
                        evidence_type=evidence["evidence_type"],
                        normalized_output=evidence,
                    )
                )
                created += 1
    return created
