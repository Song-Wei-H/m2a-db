from __future__ import annotations

from typing import Any

from app.database import async_session
from app.models import ToolRequest

__all__ = ["create_tool_request"]


async def create_tool_request(
    requested_tool: str,
    requested_capability: str,
    evidence_ref: str,
    reasoning: list[str],
) -> dict[str, Any]:
    """Create a governed capability expansion request.

    This function only inserts a ToolRequest row with
    status='pending_review'.

    No subprocesses, shell execution, approval bypass,
    or template creation occur here.
    """
    async with async_session() as session, session.begin():
        request = ToolRequest(
            requested_tool=requested_tool,
            requested_capability=requested_capability,
            evidence_ref=evidence_ref,
            reasoning_json={"reasoning": reasoning},
            status="pending_review",
            reviewer=None,
            reviewed_at=None,
        )

        session.add(request)

    return {
        "id": request.id,
        "requested_tool": request.requested_tool,
        "requested_capability": request.requested_capability,
        "status": request.status,
        "created_at": (
            request.created_at.isoformat()
            if request.created_at
            else None
        ),
    }
