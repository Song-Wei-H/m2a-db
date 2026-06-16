"""Execute allowlisted command templates via subprocess (never shell=True)."""

from __future__ import annotations

import asyncio
import logging
import subprocess
from dataclasses import dataclass

from app.config import settings
from app.mitre_rules import FORBIDDEN_TOOLS
from worker.command_templates import build_command_with_template
from worker.parsers.nmap_parser import parse_nmap_output
from worker.parsers.tool_result_parser import parse_tool_output
from worker.safety import validate_task_execution

logger = logging.getLogger(__name__)
def _to_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


@dataclass(frozen=True)
class TaskContext:
    task_id: int
    target_id: int
    tool_name: str
    host: str
    port: int | None
    protocol: str | None
    service: str | None
    open_port_id: int | None
    decision_score_id: int | None = None


@dataclass
class ToolRunOutcome:
    command: str
    raw_output: str
    parsed_result: dict
    success: bool
    status: str
    error_message: str | None = None


def build_command(ctx: TaskContext, template_row) -> tuple[list[str], str]:
    if template_row is None:
        raise ValueError("CommandTemplate required")

    template_id = validate_task_execution(ctx.tool_name, ctx.host)

    if template_id in FORBIDDEN_TOOLS:
        raise ValueError(f"Tool {ctx.tool_name!r} is forbidden")

    argv, rendered_command = build_command_with_template(template_row, ctx)
    return argv, rendered_command


def _parse_output(
    template_id: str,
    raw_output: str,
    success: bool,
    *,
    host: str | None = None,
    port: int | None = None,
    service: str | None = None,
) -> dict:
    return parse_tool_output(
        template_id,
        raw_output,
        success=success,
        host=host,
        port=port,
        service=service,
    )


def _run_subprocess(
    cmd: list[str],
    rendered_command: str,
    timeout: int,
    ctx: TaskContext,
) -> ToolRunOutcome:
    command_str = rendered_command

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )

        raw_output = (completed.stdout or "") + (
            f"\n{completed.stderr}" if completed.stderr else ""
        )

        success = completed.returncode == 0
        
        parsed = _parse_output(
            ctx.tool_name,
            raw_output,
            success,
            host=ctx.host,
            port=ctx.port,
            service=ctx.service,
        )

        return ToolRunOutcome(
            command=command_str,
            raw_output=raw_output,
            parsed_result=parsed,
            success=success,
            status="done" if success else "failed",
            error_message=None if success else f"exit_code={completed.returncode}",
        )

    except subprocess.TimeoutExpired as exc:
        raw = _to_text(exc.stdout)
        if exc.stderr:
            raw += "\n" + _to_text(exc.stderr)

        return ToolRunOutcome(
            command=command_str,
            raw_output=raw or f"timeout after {timeout}s",
            parsed_result=_parse_output(
                ctx.tool_name,
                raw or f"timeout after {timeout}s",
                success=False,
                host=ctx.host,
                port=ctx.port,
                service=ctx.service,
            ),
            success=False,
            status="failed",
            error_message=f"timeout after {timeout}s",
        )

    except FileNotFoundError as exc:
        return ToolRunOutcome(
            command=command_str,
            raw_output=str(exc),
            parsed_result=_parse_output(
                ctx.tool_name,
                str(exc),
                success=False,
                host=ctx.host,
                port=ctx.port,
                service=ctx.service,
            ),
            success=False,
            status="failed",
            error_message=str(exc),
        )


async def run_tool(
    ctx: TaskContext,
    template_row=None,
) -> ToolRunOutcome:
    argv, rendered_command = build_command(ctx, template_row)
    timeout = settings.worker_tool_timeout_seconds

    logger.info(
        "Running tool_task_id=%s tool=%s cmd=%s",
        ctx.task_id,
        ctx.tool_name,
        rendered_command,
    )

    return await asyncio.to_thread(
        _run_subprocess,
        argv,
        rendered_command,
        timeout,
        ctx,
    )
