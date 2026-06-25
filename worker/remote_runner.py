from __future__ import annotations

import httpx

from app.config import settings
from app.tool_task_constants import COMPLETED, FAILED
from worker.parsers.tool_result_parser import parse_tool_output
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
        timeout=settings.worker_tool_timeout_seconds,
        trust_env=False,
    ) as client:
        try:
            resp = await client.post(url, json=payload)
        except httpx.TimeoutException as exc:
            raise TimeoutError(
                f"remote tool timeout after {settings.worker_tool_timeout_seconds}s: "
                f"{ctx.tool_name} target={ctx.host} port={ctx.port}"
            ) from exc
        resp.raise_for_status()
        data = resp.json()

    success = data.get("status") in (
        "completed",
        "success",
        "done",
        "accepted",
    )

    raw_output = data.get("raw_output") or data.get("output") or ""

    parsed_result = data.get("parsed_result")
    if not isinstance(parsed_result, dict) or not parsed_result:
        parsed_result = parse_tool_output(
            ctx.tool_name,
            raw_output or str(data),
            success=success,
            host=ctx.host,
            port=ctx.port,
            service=ctx.service,
        )
    else:
        fallback = parse_tool_output(
            ctx.tool_name,
            raw_output,
            success=success,
            host=ctx.host,
            port=ctx.port,
            service=ctx.service,
        )
        fallback.update(parsed_result)
        parsed_result = fallback

    return ToolRunOutcome(
        command=data.get("command") or f"remote:{ctx.tool_name}",
        raw_output=raw_output or str(data),
        parsed_result=parsed_result,
        success=success,
        status=COMPLETED if success else FAILED,
        error_message=data.get("error") or data.get("message"),
    )
