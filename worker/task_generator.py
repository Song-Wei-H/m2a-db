"""Governed ToolTask generation from Decision Engine output.

This module converts deterministic decision results into either:
- a ToolRequest for governed capability expansion, or
- a ToolTask for later worker execution.

No subprocesses, shell commands, raw argv construction, or direct tool execution
occur in this module.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from app.database import async_session
from app.models import ToolRegistry, ToolTask
from worker.tool_name_normalizer import TOOL_ALIASES
from worker.tool_request_manager import create_tool_request


async def _existing_tool_task(
    target_id: int,
    open_port_id: int | None,
    tool_name: str,
) -> ToolTask | None:
    """Check if a ToolTask already exists with the same target_id, open_port_id, and tool_name
    with status in pending, running, or completed.
    """
    async with async_session() as session:
        # Build the query with proper NULL handling
        query = select(ToolTask).where(
            ToolTask.target_id == target_id,
            ToolTask.tool_name == tool_name,
            ToolTask.status.in_(["pending", "running", "completed"]),
        )
        
        # Handle NULL values properly
        if open_port_id is not None:
            query = query.where(ToolTask.open_port_id == open_port_id)
        else:
            query = query.where(ToolTask.open_port_id.is_(None))
            
        query = query.order_by(ToolTask.id.desc()).limit(1)
        
        result = await session.execute(query)
        return result.scalar_one_or_none()


def _normalize_reasoning(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]

def _safe_priority(value: Any, default: int = 5) -> int:
    try:
        priority = int(value)
    except (TypeError, ValueError):
        priority = default
    return max(0, min(priority, 100))


__all__ = ["generate_tool_task"]


async def _get_tool_registry(tool_name: str) -> ToolRegistry | None:
    """Return enabled ToolRegistry row for tool_name, or None."""
    async with async_session() as session:
        result = await session.execute(
            select(ToolRegistry)
            .where(
                ToolRegistry.tool_name == tool_name,
                ToolRegistry.enabled.is_(True),
            )
            .limit(1)
        )
        return result.scalar_one_or_none()


async def _create_request_from_decision(decision_result: dict[str, Any]) -> dict[str, Any]:
    """Create a governed ToolRequest from a request_new_template decision."""
    requested_tool = decision_result.get("requested_tool")
    requested_capability = decision_result.get("requested_capability") or "unknown"
    reasoning = decision_result.get("reasoning") or [
        "Capability expansion requested by decision engine"
    ]

    if isinstance(reasoning, str):
        reasoning = [reasoning]

    evidence_ref = decision_result.get("evidence_ref") or "decision_engine"

    tool_request = await create_tool_request(
        requested_tool=requested_tool or "unknown",
        requested_capability=requested_capability,
        evidence_ref=evidence_ref,
        reasoning=reasoning,
    )

    return {
        "action": "tool_request_created",
        "tool_task_id": None,
        "tool_request_id": tool_request.get("id"),
        "status": tool_request.get("status", "pending_review"),
    }


async def generate_tool_task(
    target_id: int,
    open_port_id: int | None,
    decision_result: dict[str, Any],
    decision_score_id: int | None = None,
) -> dict[str, Any]:
    """Create a governed ToolTask or ToolRequest from a decision result.

    The function only writes database rows. It never executes tools.
    """
    recommended_action = decision_result.get("recommended_action")
    recommended_tool = decision_result.get("recommended_tool")

    # Normalize the tool name
    if recommended_tool is not None:
        recommended_tool = TOOL_ALIASES.get(recommended_tool, recommended_tool)

    if recommended_action == "request_new_template":
        return await _create_request_from_decision(decision_result)

    if not recommended_tool:
        return {
            "action": "no_action",
            "tool_task_id": None,
            "tool_request_id": None,
            "status": "none",
        }

    # Check for existing task with same parameters (using normalized tool name)
    existing_task = await _existing_tool_task(target_id, open_port_id, recommended_tool)
    if existing_task:
        return {
            "action": "skipped_duplicate",
            "tool_name": recommended_tool,
            "existing_task_id": existing_task.id,
        }

    registry_row = await _get_tool_registry(recommended_tool)

    if registry_row is None:
        reasoning = [
            f"Recommended tool {recommended_tool!r} is not enabled in ToolRegistry"
        ]

        tool_request = await create_tool_request(
            requested_tool=recommended_tool,
            requested_capability=decision_result.get("requested_capability")
            or decision_result.get("recommended_action")
            or "unknown",
            evidence_ref=decision_result.get("evidence_ref") or "decision_engine",
            reasoning=reasoning,
        )

        return {
            "action": "tool_request_created",
            "tool_task_id": None,
            "tool_request_id": tool_request.get("id"),
            "status": tool_request.get("status", "pending_review"),
        }

    approval_required = bool(
        decision_result.get("requires_approval")
        or getattr(registry_row, "approval_required", False)
    )

    approval_status = "pending_approval" if approval_required else "not_required"

    approval_reason = "; ".join(
        _normalize_reasoning(decision_result.get("reasoning"))
    )


    async with async_session() as session, session.begin():
        task = ToolTask(
            target_id=target_id,
            open_port_id=open_port_id,
            decision_score_id=decision_score_id,
            tool_name=recommended_tool,
            status="pending",
            priority=_safe_priority(
                decision_result.get("priority")
            ),
            approval_required=approval_required,
            approval_status=approval_status,
            approval_reason=approval_reason or None,
        )

        session.add(task)
        await session.flush()

        task_id = task.id

    return {
        "action": "tool_task_created",
        "tool_task_id": task_id,
        "tool_request_id": None,
        "status": "pending",
        "approval_required": approval_required,
        "approval_status": approval_status,
    }
