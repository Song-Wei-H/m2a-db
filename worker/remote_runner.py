from __future__ import annotations

import httpx

from app.config import settings
from worker.parsers.httpx_parser import parse_httpx_output
from worker.tool_runner import TaskContext, ToolRunOutcome


async def run_remote_tool(ctx: TaskContext) -> ToolRunOutcome:
    url = settings.kali_worker_url.rstrip("/") + "/execute"

    payload = {
        "tool": ctx.tool_name,
        "target": ctx.host,
        "port": ctx.port,
        "protocol": ctx.protocol,
        "service": ctx.service,
    }

    async with httpx.AsyncClient(
        timeout=settings.worker_tool_timeout_seconds
    ) as client:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()

    success = data.get("status") in (
        "completed",
        "success",
        "done",
        "accepted",
    )

    raw_output = data.get("raw_output") or data.get("output") or ""

    if ctx.tool_name == "httpx_basic":
        parsed_result = parse_httpx_output(raw_output)
    else:
        parsed_result = data.get("parsed_result") or data

    return ToolRunOutcome(
        command=data.get("command") or f"remote:{ctx.tool_name}",
        raw_output=raw_output or str(data),
        parsed_result=parsed_result,
        success=success,
        status="completed" if success else "failed",
        error_message=data.get("error") or data.get("message"),
    )