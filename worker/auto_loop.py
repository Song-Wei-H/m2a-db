"""Auto Multi-Round Loop Implementation."""

from __future__ import annotations

import logging
from typing import Any, Dict

from sqlalchemy import select, update

from app.database import async_session
from app.models import AutoLoopDecision, DecisionScore, OpenPort, Target, ToolTask
from app.tool_task_constants import (
    ACTIVE_TASK_STATUSES as DUPLICATE_PREVENTION_STATUSES,
    APPROVED,
    COMPLETED,
    FAILED,
    NOT_REQUIRED,
    PENDING,
    PENDING_APPROVAL,
    REJECTED,
    RUNNING,
)
from worker.task_generator import generate_tool_task
from worker.tool_name_normalizer import normalize_tool_name

logger = logging.getLogger(__name__)

DISCOVERY_TOOLS = {"nmap_service", "httpx_basic", "ssh-enum", "mysql-info"}
DEPTH_TOOLS = {"nuclei_safe", "dirb_safe"}
HTTP_FOLLOWUP_TOOLS = ("nuclei_safe", "dirb_safe")

STOP_REASONS = {
    "target_completed": "target_completed",
    "max_round_reached": "max_round_reached",
    "duplicate_tool": "duplicate_tool",
    "no_next_tool": "no_next_tool",
    "stop_action": "stop_action",
    "approval_required_not_approved": "approval_required_not_approved",
}

STOP_REASON_MESSAGES = {
    STOP_REASONS["target_completed"]: "Target already completed",
    STOP_REASONS["max_round_reached"]: "Maximum round limit reached",
    STOP_REASONS["duplicate_tool"]: "Duplicate tool execution prevented",
    STOP_REASONS["no_next_tool"]: "No next tool selected",
    STOP_REASONS["stop_action"]: "Decision requested stop",
    STOP_REASONS["approval_required_not_approved"]: "Approval required before execution",
}

ACTIVE_TASK_STATUSES = {PENDING, RUNNING}
EXECUTED_OR_SKIPPED_TASK_STATUSES = {COMPLETED, FAILED, REJECTED}
HTTP_SERVICES = {"http", "https", "ssl/http", "http-alt", "www"}


def _is_http_service(service: str | None, port: int | None = None) -> bool:
    return (service or "").lower() in HTTP_SERVICES or port in {80, 443, 8000, 8080, 8443}


def _approval_status_for_tool(tool_name: str | None, requires_approval: bool) -> tuple[bool, str]:
    normalized = normalize_tool_name(tool_name)
    if not normalized:
        return False, NOT_REQUIRED
    if normalized in DEPTH_TOOLS or requires_approval:
        return True, PENDING_APPROVAL
    return False, NOT_REQUIRED


async def _existing_tool_task(
    session,
    *,
    target_id: int,
    open_port_id: int | None,
    tool_name: str,
) -> ToolTask | None:
    query = select(ToolTask).where(
        ToolTask.target_id == target_id,
        ToolTask.tool_name == tool_name,
        ToolTask.status.in_(DUPLICATE_PREVENTION_STATUSES),
    )
    if open_port_id is None:
        query = query.where(ToolTask.open_port_id.is_(None))
    else:
        query = query.where(ToolTask.open_port_id == open_port_id)
    query = query.order_by(ToolTask.id.desc()).limit(1)
    return (await session.execute(query)).scalar_one_or_none()


async def _tool_task_for_statuses(
    session,
    *,
    target_id: int,
    open_port_id: int | None,
    tool_name: str,
    statuses: set[str],
) -> ToolTask | None:
    query = select(ToolTask).where(
        ToolTask.target_id == target_id,
        ToolTask.tool_name == tool_name,
        ToolTask.status.in_(list(statuses)),
    )
    if open_port_id is None:
        query = query.where(ToolTask.open_port_id.is_(None))
    else:
        query = query.where(ToolTask.open_port_id == open_port_id)
    query = query.order_by(ToolTask.id.desc()).limit(1)
    return (await session.execute(query)).scalar_one_or_none()


async def _has_skip_record(
    session,
    *,
    target_id: int,
    round_number: int,
    tool_name: str,
) -> bool:
    result = await session.execute(
        select(AutoLoopDecision.id)
        .where(
            AutoLoopDecision.target_id == target_id,
            AutoLoopDecision.next_tool == tool_name,
            AutoLoopDecision.stop_reason.in_(
                [
                    "duplicate_tool",
                    "Duplicate tool execution prevented",
                    "approval_required",
                    "Approval required before execution",
                    "max_round_reached",
                    "Maximum round limit reached",
                    "tool_disabled",
                    "no_http_evidence",
                ]
            ),
            AutoLoopDecision.round_number <= round_number,
        )
        .order_by(AutoLoopDecision.id.desc())
        .limit(1)
    )
    return result.scalar_one_or_none() is not None


async def _http_followup_candidate(
    session,
    *,
    target: Target,
    open_port_id: int | None,
) -> dict[str, Any] | None:
    if open_port_id is None:
        return None

    current_round = target.current_round or 1
    max_round = target.max_round or 5
    if current_round >= max_round:
        return None

    port_result = await session.execute(
        select(ToolTask.open_port_id)
        .where(
            ToolTask.target_id == target.id,
            ToolTask.open_port_id == open_port_id,
            ToolTask.tool_name == "httpx_basic",
            ToolTask.status == COMPLETED,
        )
        .limit(1)
    )
    httpx_completed = port_result.scalar_one_or_none() is not None
    if not httpx_completed:
        return None

    port = await session.get(OpenPort, open_port_id)
    if port is None or not _is_http_service(port.service, port.port):
        return None

    for tool_name in HTTP_FOLLOWUP_TOOLS:
        existing = await _tool_task_for_statuses(
            session,
            target_id=target.id,
            open_port_id=open_port_id,
            tool_name=tool_name,
            statuses=ACTIVE_TASK_STATUSES | EXECUTED_OR_SKIPPED_TASK_STATUSES,
        )
        if existing is not None:
            continue
        if await _has_skip_record(
            session,
            target_id=target.id,
            round_number=current_round,
            tool_name=tool_name,
        ):
            continue
        return {
            "recommended_tool": tool_name,
            "recommended_action": "verify" if tool_name == "nuclei_safe" else "enumerate",
            "requires_approval": True,
            "priority": 80 if tool_name == "nuclei_safe" else 50,
            "reasoning": [
                f"HTTP follow-up required after httpx_basic: {tool_name}",
            ],
        }
    return None


async def check_stop_conditions(
    target_id: int,
    current_round: int,
    max_round: int,
    next_tool: str | None,
    next_action: str | None,
    existing_tool_task: ToolTask | None,
    *,
    target_status: str | None = None,
    requires_approval: bool = False,
    approval_status: str | None = None,
) -> tuple[bool, str | None]:
    """Return whether the auto loop should stop before creating another task."""
    if target_status == COMPLETED:
        return True, STOP_REASONS["target_completed"]

    if current_round >= max_round:
        return True, STOP_REASONS["max_round_reached"]

    if not next_tool:
        return True, STOP_REASONS["no_next_tool"]

    if next_action == "stop":
        return True, STOP_REASONS["stop_action"]

    if existing_tool_task is not None:
        return True, STOP_REASONS["duplicate_tool"]

    if requires_approval and approval_status not in {APPROVED, NOT_REQUIRED}:
        return True, STOP_REASONS["approval_required_not_approved"]

    return False, None


async def _record_loop_decision(
    session,
    *,
    target_id: int,
    round_number: int,
    stop_reason: str,
    next_tool: str | None = None,
) -> None:
    decision = AutoLoopDecision(
        target_id=target_id,
        round_number=round_number,
        stop_reason=stop_reason,
        next_tool=next_tool,
    )
    session.add(decision)
    await session.flush()


async def target_has_active_tasks(session, target_id: int) -> bool:
    result = await session.execute(
        select(ToolTask.id)
        .where(
            ToolTask.target_id == target_id,
            ToolTask.status.in_(ACTIVE_TASK_STATUSES),
        )
        .limit(1)
    )
    return result.scalar_one_or_none() is not None


async def target_has_missing_http_followups(session, target: Target) -> bool:
    ports = list(
        (
            await session.execute(
                select(OpenPort)
                .where(OpenPort.target_id == target.id)
                .order_by(OpenPort.id)
            )
        )
        .scalars()
        .all()
    )
    for port in ports:
        if not _is_http_service(port.service, port.port):
            continue
        candidate = await _http_followup_candidate(
            session,
            target=target,
            open_port_id=port.id,
        )
        if candidate is not None:
            return True
    return False


async def _create_final_audit_decision_if_needed(session, target_id: int) -> bool:
    latest_result = await session.execute(
        select(DecisionScore)
        .where(DecisionScore.target_id == target_id)
        .order_by(DecisionScore.created_at.desc(), DecisionScore.id.desc())
        .limit(1)
    )
    latest = latest_result.scalar_one_or_none()
    if latest is None:
        return False

    if latest.next_action != "continue" or not latest.next_tool:
        return False

    normalized_tool = normalize_tool_name(latest.next_tool)
    task_query = select(ToolTask.id).where(
        ToolTask.target_id == target_id,
        ToolTask.tool_name == normalized_tool,
        ToolTask.status.in_([COMPLETED, FAILED]),
    )
    if latest.open_port_id is None:
        task_query = task_query.where(ToolTask.open_port_id.is_(None))
    else:
        task_query = task_query.where(ToolTask.open_port_id == latest.open_port_id)
    task_query = task_query.limit(1)

    completed_task = (await session.execute(task_query)).scalar_one_or_none()
    if completed_task is None:
        return False

    session.add(
        DecisionScore(
            target_id=target_id,
            open_port_id=latest.open_port_id,
            risk_score=latest.risk_score or 0,
            base_risk_score=latest.base_risk_score,
            adjusted_risk_score=latest.adjusted_risk_score,
            confidence_score=latest.confidence_score,
            learning_adjustment=latest.learning_adjustment,
            runtime_adjustment=latest.runtime_adjustment,
            evidence_adjustment=latest.evidence_adjustment,
            waf_detected=latest.waf_detected,
            tool_blocked=latest.tool_blocked,
            tool_timeout=latest.tool_timeout,
            severity=latest.severity,
            next_action="stop",
            next_tool=None,
            mitre_phase=latest.mitre_phase,
            mitre_technique=latest.mitre_technique,
            confidence=latest.confidence,
            reason="Target completed; no further executable tasks.",
            reasoning=["Target has no pending/running ToolTask and the recommended next tool already finished."],
            input_snapshot={
                "stage": "final_audit",
                "previous_decision_score_id": latest.id,
                "completed_tool": normalized_tool,
            },
        )
    )
    await session.flush()
    return True


async def finalize_target_if_idle(
    target_id: int,
    *,
    session=None,
    stop_reason: str | None = None,
) -> bool:
    """Mark target completed when no pending/running ToolTask remains."""
    if session is None:
        async with async_session() as owned_session, owned_session.begin():
            return await finalize_target_if_idle(
                target_id,
                session=owned_session,
                stop_reason=stop_reason,
            )

    if await target_has_active_tasks(session, target_id):
        return False

    target = await session.get(Target, target_id)
    if target is None:
        return False

    current_round = target.current_round or 1
    max_round = target.max_round or 5
    if current_round < max_round and await target_has_missing_http_followups(session, target):
        logger.info("target_id=%s not completed: pending HTTP follow-up tools remain", target_id)
        return False

    await _create_final_audit_decision_if_needed(session, target_id)

    await session.execute(
        update(Target)
        .where(Target.id == target_id)
        .values(status=COMPLETED)
    )
    if stop_reason:
        logger.info("target_id=%s completed stop_reason=%s", target_id, stop_reason)
    return True


async def get_next_tool_task(target_id: int, open_port_id: int | None, decision_result: Dict[str, Any]) -> Dict[str, Any]:
    """Generate the next tool task with auto-loop stop and approval controls."""
    followup_decision: dict[str, Any] | None = None
    async with async_session() as session, session.begin():
        target = await session.get(Target, target_id)
        if not target:
            return {"action": "stop", "stop_reason": "target_not_found"}

        current_round = target.current_round or 1
        max_round = getattr(target, "max_round", None)
        if max_round is None:
            max_round = getattr(target, "max_rounds", None)
        max_round = max_round or 5
        next_action = decision_result.get("recommended_action")
        next_tool = normalize_tool_name(decision_result.get("recommended_tool"))
        requires_approval, approval_status = _approval_status_for_tool(
            next_tool,
            bool(decision_result.get("requires_approval")),
        )

        existing_task = None
        if next_tool:
            existing_task = await _existing_tool_task(
                session,
                target_id=target_id,
                open_port_id=open_port_id,
                tool_name=next_tool,
            )

        should_stop, stop_reason = await check_stop_conditions(
            target_id,
            current_round,
            max_round,
            next_tool,
            next_action,
            existing_task,
            target_status=target.status,
        )

        if should_stop and stop_reason in {
            STOP_REASONS["no_next_tool"],
            STOP_REASONS["stop_action"],
            STOP_REASONS["duplicate_tool"],
        }:
            followup_decision = await _http_followup_candidate(
                session,
                target=target,
                open_port_id=open_port_id,
            )
            if followup_decision is not None:
                followup_decision = {
                    **decision_result,
                    **followup_decision,
                    "decision_score_id": decision_result.get("decision_score_id"),
                }
                should_stop = False
            else:
                reason = STOP_REASON_MESSAGES.get(stop_reason or "", stop_reason or "unknown")
                await _record_loop_decision(
                    session,
                    target_id=target_id,
                    round_number=current_round,
                    stop_reason=reason,
                    next_tool=next_tool,
                )
                completed = await finalize_target_if_idle(
                    target_id,
                    session=session,
                    stop_reason=reason,
                )
                return {
                    "action": "stop",
                    "stop_reason": stop_reason,
                    "reason": reason,
                    "existing_task_id": getattr(existing_task, "id", None),
                    "target_completed": completed,
                }

        if should_stop:
            reason = STOP_REASON_MESSAGES.get(stop_reason or "", stop_reason or "unknown")
            await _record_loop_decision(
                session,
                target_id=target_id,
                round_number=current_round,
                stop_reason=reason,
                next_tool=next_tool,
            )
            completed = await finalize_target_if_idle(
                target_id,
                session=session,
                stop_reason=reason,
            )
            return {
                "action": "stop",
                "stop_reason": stop_reason,
                "reason": reason,
                "existing_task_id": getattr(existing_task, "id", None),
                "target_completed": completed,
            }

    if followup_decision is not None:
        next_tool = normalize_tool_name(followup_decision.get("recommended_tool"))
        requires_approval, _ = _approval_status_for_tool(
            next_tool,
            bool(followup_decision.get("requires_approval")),
        )
        normalized_decision = {
            **followup_decision,
            "recommended_tool": next_tool,
            "requires_approval": requires_approval,
        }
        task_result = await generate_tool_task(
            target_id=target_id,
            open_port_id=open_port_id,
            decision_result=normalized_decision,
            decision_score_id=followup_decision.get("decision_score_id"),
        )
        if task_result.get("action") == "tool_task_created" and requires_approval:
            task_result["approval_required"] = True
            task_result["approval_status"] = PENDING_APPROVAL
        return task_result

    normalized_decision = {
        **decision_result,
        "recommended_tool": next_tool,
        "requires_approval": requires_approval,
    }
    task_result = await generate_tool_task(
        target_id=target_id,
        open_port_id=open_port_id,
        decision_result=normalized_decision,
        decision_score_id=decision_result.get("decision_score_id"),
    )
    if task_result.get("action") == "tool_task_created" and requires_approval:
        task_result["approval_required"] = True
        task_result["approval_status"] = PENDING_APPROVAL
    return task_result


async def increment_target_round(target_id: int) -> None:
    """Increment the target's current round without exceeding max_round."""
    async with async_session() as session, session.begin():
        target = await session.get(Target, target_id)
        if target:
            current_round = target.current_round or 1
            max_round = target.max_round or 5
            target.current_round = min(current_round + 1, max_round)
            await session.flush()


async def log_auto_loop_decision(
    target_id: int,
    round_number: int,
    stop_reason: str,
    next_tool: str | None = None,
) -> None:
    """Log the auto loop decision."""
    async with async_session() as session, session.begin():
        await _record_loop_decision(
            session,
            target_id=target_id,
            round_number=round_number,
            stop_reason=stop_reason,
            next_tool=next_tool,
        )
