"""Re-validate tasks at worker boundary before subprocess."""

from __future__ import annotations

from app.security.scope import assert_target_in_scope
from app.security.tool_policy import resolve_template_tool
from app.tool_task_constants import APPROVED, EXECUTABLE_APPROVAL_STATUSES, NOT_REQUIRED


def validate_task_execution(
    tool_name: str,
    target: str,
    approval_required: bool = False,
    approval_status: str = NOT_REQUIRED,
) -> str:
    """Return canonical template tool id or raise ValueError.

    Final worker-boundary checks before execution.

    Template existence and enabled-state validation are handled by:
    - worker/task_poller.py
    - CommandTemplate lookup in the active worker path
    - CommandTemplate.enabled
    """

    template_id = resolve_template_tool(tool_name)

    status = (approval_status or "").strip().lower()

    if status not in EXECUTABLE_APPROVAL_STATUSES:
        raise ValueError(f"Invalid approval_status for execution: {approval_status!r}")

    if approval_required and status != APPROVED:
        raise ValueError("Task requires human approval")

    assert_target_in_scope(target)

    return template_id
