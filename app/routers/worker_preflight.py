"""Read-only Kali Worker capability preflight.

This endpoint deliberately contacts only the configured worker health endpoint.
It never submits a target, ToolTask, command, or credentials to the worker.
"""

from __future__ import annotations

import httpx
from fastapi import APIRouter

from app.config import settings
from app.tool_catalog import CANONICAL_ALLOWED_TOOLS

router = APIRouter(prefix="/workers", tags=["workers"])


@router.get("/preflight")
async def worker_preflight() -> dict:
    worker_url = settings.kali_worker_url.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:
            response = await client.get(f"{worker_url}/health")
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        return {
            "worker_url": worker_url,
            "reachable": False,
            "status": "WORKER_PREFLIGHT_FAILED",
            "error": str(exc),
            "worker_tools": [],
            "m2a_allowed_tools": sorted(CANONICAL_ALLOWED_TOOLS),
        }

    raw_tools = payload.get("allowed_tools") or payload.get("tools") or []
    worker_tools = sorted({str(tool).lower() for tool in raw_tools if isinstance(tool, str)})
    m2a_tools = set(settings.allowed_tools_list) & set(CANONICAL_ALLOWED_TOOLS)
    missing_on_worker = sorted(m2a_tools - set(worker_tools))
    unsupported_by_m2a = sorted(set(worker_tools) - set(CANONICAL_ALLOWED_TOOLS))
    return {
        "worker_url": worker_url,
        "reachable": True,
        "status": "READY" if not missing_on_worker else "CAPABILITY_MISMATCH",
        "worker_status": payload.get("status"),
        "worker_tools": worker_tools,
        "m2a_allowed_tools": sorted(m2a_tools),
        "missing_on_worker": missing_on_worker,
        "unsupported_by_m2a": unsupported_by_m2a,
        "version_verification": {
            "state": "REQUESTED_NOT_DEPLOYED",
            "tool": "http_version_verify",
            "reason": "Not in the M2A canonical catalog until the worker advertises and its parser contract is validated.",
        },
    }
