from __future__ import annotations

import logging
import hashlib
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import httpx

from app.config import settings
from app.tool_task_constants import COMPLETED, FAILED
from worker.parsers.tool_result_parser import parse_tool_output
from worker.tool_runner import TaskContext, ToolRunOutcome
from app.execution_trace import execution_request
from app.execution_governance import parameter_hash
from app.action_contracts import ACTION_IDENTITIES, ACTION_TEMPLATES, canonical_action_parameters

logger = logging.getLogger(__name__)


LEGACY_L1_ACTION = "http_security_headers.collect.v1"
LEGACY_L1_TARGET = "10.56.66.119"
LEGACY_L1_PORT = 18080


def _legacy_l1_payload(ctx: TaskContext) -> dict:
    """Down-convert only the fixed, locally authorized L1 contract for the old API."""
    if os.environ.get("M2A_WORKER_API_MODE") != "legacy":
        raise ValueError("legacy adapter was called outside explicit legacy mode")
    run_id = os.environ.get("GADE_L1_RUN_ID", "")
    output = os.environ.get("GADE_L1_OUTPUT", "")
    if not re.fullmatch(r"[0-9a-f]{12}", run_id) or not output:
        raise ValueError("legacy adapter is restricted to the isolated GADE L1 runner")
    expected_output_root = (Path(__file__).resolve().parents[1] / "experiments" / "gade-seven-level-v1"
                            / "real-worker-l1" / "local-only").resolve()
    resolved_output = Path(output).resolve()
    if resolved_output.parent != expected_output_root or resolved_output.name != run_id:
        raise ValueError("legacy adapter output path is outside the exact run-scoped evidence allowlist")
    try:
        UUID(ctx.request_id or "")
        UUID(ctx.correlation_id or "")
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("legacy adapter requires UUID request and experiment correlation IDs") from exc
    expected = canonical_action_parameters(
        action_id=LEGACY_L1_ACTION, target=LEGACY_L1_TARGET,
        port=LEGACY_L1_PORT, protocol="tcp", service="http",
    )
    if (ctx.action_id != LEGACY_L1_ACTION or ctx.tool_name != "http_security_headers"
            or ctx.host != LEGACY_L1_TARGET or ctx.port != LEGACY_L1_PORT
            or ctx.protocol != "tcp" or ctx.service != "http"
            or ctx.authorization_id is None or ctx.task_id is None
            or ctx.execution_identity != ACTION_IDENTITIES[LEGACY_L1_ACTION]
            or ctx.template_id != ACTION_TEMPLATES[LEGACY_L1_ACTION]
            or ctx.authorization_parameters != expected
            or ctx.authorization_parameters_hash != parameter_hash(expected)
            or not ctx.request_id or not ctx.correlation_id):
        raise ValueError("legacy adapter refused non-canonical or uncorrelated authorization")
    # These are the only fields used by the inspected legacy HTTP handler. The
    # local full request/grant remains persisted separately in ToolTask.
    return {"tool": ctx.tool_name, "target": ctx.host,
            "port": ctx.port, "service": ctx.service}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _legacy_result_matches(ctx: TaskContext, data: dict) -> bool:
    parsed = data.get("parsed_result")
    if not isinstance(parsed, dict) or parsed.get("success") is not True:
        return False
    return (parsed.get("tool_name") == ctx.tool_name
            and parsed.get("host") == ctx.host
            and parsed.get("port") == ctx.port
            and parsed.get("method") == "HEAD"
            and isinstance(parsed.get("status_code"), int)
            and 100 <= parsed["status_code"] <= 599)


async def run_remote_tool(ctx: TaskContext) -> ToolRunOutcome:
    url = settings.kali_worker_url.rstrip("/") + "/execute"

    api_mode = os.environ.get("M2A_WORKER_API_MODE", "native").strip().lower()
    if api_mode not in {"native", "legacy"}:
        raise ValueError(f"unsupported Worker API mode: {api_mode}")
    governance_payload = execution_request(ctx)
    payload = _legacy_l1_payload(ctx) if api_mode == "legacy" else governance_payload
    request_sent_at = _utc_now()

    async with httpx.AsyncClient(
        timeout=settings.worker_tool_timeout_seconds,
        trust_env=False,
    ) as client:
        try:
            resp = await client.post(url, json=payload)
        except httpx.TimeoutException as exc:
            logger.exception("worker_request_timeout request_id=%s tool_task_id=%s",
                             ctx.request_id, ctx.task_id)
            raise TimeoutError(
                f"remote tool timeout request_id={ctx.request_id} after {settings.worker_tool_timeout_seconds}s: "
                f"{ctx.tool_name} target={ctx.host} port={ctx.port}"
            ) from exc
        response_text = resp.text
        response_received_at = _utc_now()
        worker_date = getattr(resp, "headers", {}).get("date")
        try:
            data = resp.json()
        except ValueError:
            data = None

    valid_envelope = isinstance(data, dict)
    application_status = data.get("status") if valid_envelope else None
    parsed_response = data.get("parsed_result") if valid_envelope else None
    success = (application_status in ("completed", "success", "done")
               and not (isinstance(parsed_response, dict) and parsed_response.get("success") is False))
    receipt = data.get("execution_receipt") if valid_envelope else None
    trace_error = None
    response_hash = parameter_hash(data if valid_envelope else response_text)
    response_output = ((data.get("raw_output") or data.get("output") or "")
                       if valid_envelope else response_text)
    worker_exchange = {
        "api_mode": api_mode,
        "request_id": ctx.request_id,
        "correlation_id": ctx.correlation_id,
        "task_id": ctx.task_id,
        "authorization_id": ctx.authorization_id,
        "expected_worker_build_sha256": ctx.expected_worker_build_sha256,
        "delivery": "response_received",
        "request_sent_at_utc": request_sent_at,
        "response_received_at_utc": response_received_at,
        "worker_http_date": worker_date,
        "http_status": resp.status_code,
        "application_status": application_status,
        "receipt_present": isinstance(receipt, dict),
        "response_sha256": response_hash,
        "output_sha256": hashlib.sha256(str(response_output).encode("utf-8", errors="replace")).hexdigest(),
        "governance_request_sha256": parameter_hash(governance_payload),
        "http_request": {"method": "POST", "url": url, "body": payload},
        "http_response": {"status_code": resp.status_code, "date": worker_date,
                           "body": data if valid_envelope else response_text},
    }
    if api_mode == "legacy":
        success = (200 <= resp.status_code < 300
                   and valid_envelope
                   and application_status == "completed"
                   and _legacy_result_matches(ctx, data))
        trace_error = None if success else "Legacy Worker response did not establish action success"
        worker_exchange.update({
            "native_receipt_status": "NATIVE_WORKER_RECEIPT_UNAVAILABLE",
            "legacy_result_fields_valid": bool(valid_envelope and _legacy_result_matches(ctx, data)),
            "receipt_valid": False,
            "trace_error": "NATIVE_WORKER_RECEIPT_UNAVAILABLE",
        })
    else:
        worker_exchange["receipt_valid"] = False
        worker_exchange["trace_error"] = None
    if resp.status_code < 200 or resp.status_code >= 300:
        trace_error = f"Worker returned HTTP {resp.status_code}"
        success = False
    elif not valid_envelope:
        trace_error = "Worker response was not a JSON object"
        success = False
    if api_mode == "native" and ctx.authorization_id is not None and trace_error is None:
        if not isinstance(receipt, dict):
            trace_error = "Worker execution receipt missing"
        elif (receipt.get("request_hash") != parameter_hash(payload)
              or receipt.get("request_id") != ctx.request_id
              or receipt.get("correlation_id") != ctx.correlation_id
              or receipt.get("worker_build_sha256") != ctx.expected_worker_build_sha256
              or receipt.get("task_id") != ctx.task_id
              or receipt.get("authorization_id") != ctx.authorization_id
              or receipt.get("template_id") != ctx.template_id
              or receipt.get("executed_parameters") != ctx.authorization_parameters
              or receipt.get("executed_action") != ctx.action_id
              or receipt.get("execution_identity") != ctx.execution_identity
              or receipt.get("worker_replay_claim") != "PERSISTED_SINGLE_USE"
              or receipt.get("handler_invoked") is not True
              or receipt.get("execution_outcome") != application_status
              or not receipt.get("request_received_at_utc")
              or not receipt.get("handler_started_at_utc")
              or not receipt.get("handler_completed_at_utc")
              or not isinstance(receipt.get("worker_build_sha256"), str)
              or len(receipt.get("worker_build_sha256", "")) != 64
              or receipt.get("worker_build_sha256") != ctx.expected_worker_build_sha256
              or any(ch not in "0123456789abcdef" for ch in receipt.get("worker_build_sha256", "").lower())
              or receipt.get("action_success") != success
              or not isinstance(receipt.get("action_success"), bool)):
            trace_error = "Worker authority-to-execution drift"
        if trace_error:
            success = False

    if api_mode == "native":
        worker_exchange["receipt_valid"] = trace_error is None and isinstance(receipt, dict)
        worker_exchange["trace_error"] = trace_error
    logger.info("worker_response request_id=%s tool_task_id=%s http_status=%s application_status=%s "
                "receipt_present=%s receipt_valid=%s response_sha256=%s",
                ctx.request_id, ctx.task_id, resp.status_code, application_status,
                worker_exchange["receipt_present"], worker_exchange["receipt_valid"], response_hash)

    raw_output = ((data.get("raw_output") or data.get("output") or "")
                  if valid_envelope else response_text)

    parsed_result = data.get("parsed_result") if valid_envelope else None
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
        # Audit-only string returned by the remote worker. The local worker
        # never executes this value; local execution remains template/argv
        # based in worker.tool_runner with shell=False.
        command=(data.get("command") or f"remote:{ctx.tool_name}") if valid_envelope else f"remote:{ctx.tool_name}",
        raw_output=raw_output or (str(data) if valid_envelope else ""),
        parsed_result=parsed_result,
        success=success,
        status=COMPLETED if success else FAILED,
        error_message=((trace_error or data.get("error") or data.get("message")
                       or (None if success else f"Worker application outcome: {application_status}"))
                       if api_mode == "native" else (None if success else trace_error))
                       if valid_envelope else trace_error,
        execution_receipt=(data.get("execution_receipt") if valid_envelope else None)
                          if api_mode == "native" else None,
        worker_exchange=worker_exchange,
    )
