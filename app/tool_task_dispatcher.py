"""
Dispatcher: validate LLM JSON proposals and enqueue tool_tasks.
LLM never touches subprocess — only this layer writes tasks.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import Target, ToolTask, ToolRegistry, ToolRequest
from app.security.llm_schema import LlmToolProposal
from app.security.tool_policy import (
    parse_llm_payload,
    resolve_template_tool,
    validate_profile,
)
from app.tool_catalog import DEPTH_VALIDATION_TOOLS, SAFE_DISCOVERY_TOOLS

def _determine_approval_from_risk_level(tool_name: str, risk_level: str) -> tuple[bool, str, str | None]:
    if tool_name in SAFE_DISCOVERY_TOOLS:
        return False, "not_required", None
    if tool_name in DEPTH_VALIDATION_TOOLS:
        if risk_level in ("critical", "high"):
            return True, "pending_approval", "High-risk validation requires human approval"
        return False, "not_required", None
    return True, "pending_approval", "Unknown or uncategorized tool requires human approval"

logger = logging.getLogger(__name__)


@dataclass
class DispatchResult:
    accepted: bool
    tool_task_id: int | None
    status: str
    message: str
    proposal: LlmToolProposal | None = None


async def _reject_task(
    db: AsyncSession,
    *,
    target_id: int | None,
    tool_name: str,
    reason: str,
    open_port_id: int | None = None,
) -> DispatchResult:
    if target_id is None:
        logger.warning("tool_task rejected (no DB row): %s", reason)
        return DispatchResult(
            accepted=False,
            tool_task_id=None,
            status="rejected",
            message=reason,
        )

    row = ToolTask(
        target_id=target_id,
        open_port_id=open_port_id,
        tool_name=tool_name[:100],
        status="rejected",
        reject_reason=reason[:2000],
        priority=9,
    )
    db.add(row)
    await db.flush()
    logger.warning("tool_task rejected id=%s reason=%s", row.id, reason)
    return DispatchResult(
        accepted=False,
        tool_task_id=row.id,
        status="rejected",
        message=reason,
    )


def _tool_allowed_by_config(template_tool: str) -> bool:
    allowed = settings.allowed_tools_list
    return not allowed or template_tool in allowed


async def dispatch_llm_tool_proposal(
    db: AsyncSession,
    raw_payload: Any,
    *,
    profile: str,
    target_id: int | None = None,
    open_port_id: int | None = None,
) -> DispatchResult:
    """
    Validate LLM JSON and create pending tool_task, or rejected on failure.
    Rejects any payload containing command/shell fields.
    """
    # Disallow unsafe or approval fields from LLM payload
    tool_hint = "unknown"

    if isinstance(raw_payload, dict):
        tool_hint = str(raw_payload.get("tool", "unknown"))

    disallowed_keys = {
        "command",
        "shell",
        "args",
        "timeout",
        "hydra",
        "approval_required",
        "approval_status",
        "approval_reason",
        "approved_by",
        "approved_at",
    }

    if isinstance(raw_payload, dict) and any(
    k in raw_payload
    for k in disallowed_keys
):
        return await _reject_task(
            db,
            target_id=target_id,
            tool_name=tool_hint,
            reason="LLM payload contains disallowed keys",
            open_port_id=open_port_id,
        )

    try:
        proposal = parse_llm_payload(raw_payload)
    except Exception as exc:
        return await _reject_task(
            db,
            target_id=target_id,
            tool_name=tool_hint,
            reason=f"LLM validation failed: {exc}",
            open_port_id=open_port_id,
        )

    # Resolve template tool and check allowed
    template_tool = resolve_template_tool(proposal.tool)
    if not _tool_allowed_by_config(template_tool):
        return await _reject_task(
            db,
            target_id=target_id,
            tool_name=template_tool,
            reason=f"Tool {template_tool!r} not allowed by config",
            open_port_id=open_port_id,
        )

    # Target lookup / validation
    target_row = None
    if target_id is None:
        host_stmt = select(Target).where(Target.target == proposal.target).limit(1)
        target_row = (await db.execute(host_stmt)).scalar_one_or_none()
        if target_row is None:
            return await _reject_task(
                db,
                target_id=None,
                tool_name=template_tool,
                reason=f"Target {proposal.target!r} not registered",
                open_port_id=open_port_id,
            )
        target_id = target_row.id
    else:
        host_stmt = select(Target).where(Target.id == target_id).limit(1)
        target_row = (await db.execute(host_stmt)).scalar_one_or_none()
        if (
            target_row is None
            or target_row.target.strip() != proposal.target.strip()
        ):
            return await _reject_task(
                db,
                target_id=target_id,
                tool_name=template_tool,
                reason=f"Target mismatch for id {target_id}",
                open_port_id=open_port_id,
            )

    # Validate profile against target scope
    validate_profile(profile, target_row.scope if target_row else None)

    # Determine approval fields
    approval_required, approval_status, approval_reason = _determine_approval_from_risk_level(
        template_tool, proposal.risk_level
    )

    # Create ToolTask
    # ToolRegistry lookup
    reg_stmt = select(ToolRegistry).where(ToolRegistry.tool_name == template_tool).limit(1)
    reg_row = (await db.execute(reg_stmt)).scalar_one_or_none()
    if reg_row is None or not reg_row.enabled:
        # Create ToolRequest
        request_status = "pending_review"
        request_reason = "Tool not registered" if reg_row is None else "Tool disabled"
        req = ToolRequest(
            requested_tool=template_tool[:100],
            requested_capability="tool_execution",
            evidence_ref=f"target_id={target_id};open_port_id={open_port_id}",
            reasoning_json={
                "reason": request_reason,
                "requested_by": "llm",
                "status": request_status,
                "profile": profile,
                "target_id": target_id,
                "open_port_id": open_port_id,
                "proposal_reason": proposal.reason,
            },
            status=request_status,
        )
        db.add(req)
        await db.flush()
        logger.info(
            "tool_task pending request id=%s tool=%s",
            req.id,
            template_tool,
        )
        return DispatchResult(
            accepted=False,
            tool_task_id=None,
            status="pending_tool_request",
            message="Tool not registered; request created" if reg_row is None else "Tool disabled; request created",
        )
    # Continue normal creation
    task = ToolTask(
        target_id=target_id,
        open_port_id=open_port_id,
        tool_name=template_tool,
        status="pending",
        priority=_priority_from_risk(proposal.risk_level),
        approval_required=approval_required,
        approval_status=approval_status,
        approval_reason=approval_reason,
    )
    db.add(task)
    await db.flush()

    logger.info(
        "tool_task accepted id=%s tool=%s target=%s profile=%s",
        task.id,
        template_tool,
        proposal.target,
        profile,
    )
    return DispatchResult(
        accepted=True,
        tool_task_id=task.id,
        status="pending",
        message=proposal.reason,
        proposal=proposal,
    )


def _priority_from_risk(risk_level: str) -> int:
    return {
        "critical": 1,
        "high": 2,
        "medium": 3,
        "low": 4,
        "info": 5,
    }.get(risk_level, 5)
