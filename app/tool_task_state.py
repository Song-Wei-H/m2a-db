"""State transition helpers for ToolTask lifecycle fields."""

from __future__ import annotations

from typing import Any

from app.tool_task_constants import (
    APPROVAL_REJECTED,
    APPROVED,
    CANCELLED,
    COMPLETED,
    FAILED,
    NOT_REQUIRED,
    PENDING,
    PENDING_APPROVAL,
    REJECTED,
    RUNNING,
    VALID_APPROVAL_STATUSES,
    VALID_TASK_STATUSES,
)

TASK_TRANSITIONS: dict[str, set[str]] = {
    PENDING: {RUNNING, FAILED, CANCELLED, REJECTED},
    RUNNING: {COMPLETED, FAILED, CANCELLED, REJECTED},
    COMPLETED: set(),
    FAILED: set(),
    CANCELLED: set(),
    REJECTED: set(),
}

APPROVAL_TRANSITIONS: dict[str, set[str]] = {
    NOT_REQUIRED: set(),
    PENDING_APPROVAL: {APPROVED, APPROVAL_REJECTED},
    APPROVED: set(),
    APPROVAL_REJECTED: set(),
}


def validate_tool_task_transition(current_status: str, next_status: str) -> None:
    if current_status not in VALID_TASK_STATUSES:
        raise ValueError(f"Unknown ToolTask status: {current_status!r}")
    if next_status not in VALID_TASK_STATUSES:
        raise ValueError(f"Unknown ToolTask status: {next_status!r}")
    if next_status not in TASK_TRANSITIONS[current_status]:
        raise ValueError(
            f"Invalid ToolTask status transition: {current_status!r} -> {next_status!r}"
        )


def tool_task_status_values(
    current_status: str,
    next_status: str,
    **extra_values: Any,
) -> dict[str, Any]:
    validate_tool_task_transition(current_status, next_status)
    return {"status": next_status, **extra_values}


def validate_approval_transition(current_status: str, next_status: str) -> None:
    if current_status not in VALID_APPROVAL_STATUSES:
        raise ValueError(f"Unknown approval status: {current_status!r}")
    if next_status not in VALID_APPROVAL_STATUSES:
        raise ValueError(f"Unknown approval status: {next_status!r}")
    if next_status not in APPROVAL_TRANSITIONS[current_status]:
        raise ValueError(
            f"Invalid approval status transition: {current_status!r} -> {next_status!r}"
        )


def approval_status_values(
    current_status: str,
    next_status: str,
    **extra_values: Any,
) -> dict[str, Any]:
    validate_approval_transition(current_status, next_status)
    return {"approval_status": next_status, **extra_values}
