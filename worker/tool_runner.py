"""Execute allowlisted command templates via subprocess (never shell=True)."""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
from dataclasses import dataclass

from app.config import settings
from app.mitre_rules import FORBIDDEN_TOOLS
from worker.command_templates import build_command_with_template
from worker.parsers.httpx_parser import parse_httpx_output
from worker.parsers.ssh_enum_parser import parse_ssh_enum_output
from worker.parsers.nmap_parser import parse_nmap_output
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


def _parse_output(template_id: str, raw_output: str, success: bool) -> dict:
    if template_id == "httpx_basic":
        parsed = parse_httpx_output(raw_output)

    elif template_id == "nuclei_safe":
        findings: list[dict] = []

        for line in raw_output.splitlines():
            line = line.strip()

            if not line:
                continue

            try:
                row = json.loads(line)

                if isinstance(row, dict):
                    findings.append(row)

            except json.JSONDecodeError:
                continue

        parsed = {
            "tool": "nuclei_safe",
            "finding_count": len(findings),
            "findings": findings[:50],
        }

    elif template_id == "ssh-enum":
        parsed = parse_ssh_enum_output(raw_output)
        parsed["status"] = "done" if success else "failed"
        return parsed
    elif template_id == "nmap_service":
        parsed = {
            "tool": "nmap_service",
            "status": "done" if success else "failed",
            "open_ports": parse_nmap_output(raw_output)
        }
        return parsed

    else:
        parsed = {
            "tool": template_id,
            "line_count": len(raw_output.splitlines()),
            "preview": raw_output[:4000],
        }

    parsed["status"] = "done" if success else "failed"
    return parsed


def _run_subprocess(
    cmd: list[str],
    rendered_command: str,
    timeout: int,
    tool_name: str,
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
        
        parsed = _parse_output(tool_name, raw_output, success)

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
            parsed_result={
                "status": "failed",
                "error": "timeout",
            },
            success=False,
            status="failed",
            error_message=f"timeout after {timeout}s",
        )

    except FileNotFoundError as exc:
        return ToolRunOutcome(
            command=command_str,
            raw_output=str(exc),
            parsed_result={
                "status": "failed",
                "error": "not_found",
            },
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
        ctx.tool_name,
    )