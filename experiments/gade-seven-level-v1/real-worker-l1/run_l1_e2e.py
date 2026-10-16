"""One real, scoped L1 governance path against an isolated PostgreSQL database.

The host runner supplies exact, run-scoped environment variables. This module
uses production governance and execute_task(task_id); it never batch-polls.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy import func, select, text

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from app.action_contracts import ACTION_IDENTITIES, ACTION_TEMPLATES, ACTION_REQUIRED_ATTACK_DEPTH
from app.attack_authorization import POLICY_VERSION
from app.config import settings
from app.database import async_session, engine
from app.execution_governance import canonical_parameters, evaluate_and_authorize
from app.execution_trace import context_evidence, row_dict, trace_tool_result
from app.models import (AuthorizationDecision, CommandTemplate, ExecutionAuthorization,
                        OpenPort, Target, ToolRegistry, ToolResult, ToolTask, ValidationAction)
from app.tool_task_writer import create_tool_task_if_not_exists
from worker.task_poller import execute_task

TARGET = "10.56.66.119"
PORT = 18080
SCOPE = "10.56.66.119/32"
TOOL = "http_security_headers"
ACTION = "http_security_headers.collect.v1"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def save(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")


async def run() -> None:
    run_id = os.environ.get("GADE_L1_RUN_ID", "")
    output = Path(os.environ.get("GADE_L1_OUTPUT", ""))
    require(len(run_id) == 12 and all(c in "0123456789abcdef" for c in run_id), "invalid exact run ID")
    correlation_id = os.environ.get("GADE_L1_CORRELATION_ID", "")
    try:
        UUID(correlation_id)
    except (ValueError, TypeError, AttributeError) as exc:
        raise RuntimeError("invalid experiment correlation ID") from exc
    require(output.is_dir(), "output directory missing")
    require(settings.enforce_target_scope, "ENFORCE_TARGET_SCOPE must be true")
    require(settings.allowed_scopes_list == [SCOPE], "only the exact Lab /32 is allowed")
    require(settings.kali_worker_url.rstrip("/") == "http://10.56.64.121:8001", "Dedicated GADE Worker endpoint drift")
    url = urlsplit(settings.database_url)
    require(url.hostname == "127.0.0.1" and url.port == int(os.environ["GADE_L1_DB_PORT"]), "database endpoint drift")
    require(url.path.lstrip("/") == f"gade_{run_id}_fresh", "database identity drift")
    require(ACTION_REQUIRED_ATTACK_DEPTH[ACTION] == 1, "action depth drift")

    state = {"run_id": run_id, "started_utc": datetime.now(timezone.utc).isoformat(),
             "environment": {"database": url.path.lstrip("/"), "port": url.port,
                             "scope": SCOPE, "worker_url": settings.kali_worker_url,
                             "policy_version": POLICY_VERSION},
             "action": ACTION, "tool": TOOL, "proposal_source": "deterministic",
             "api_mode": os.environ.get("M2A_WORKER_API_MODE", "native"),
             "experiment_correlation_id": correlation_id,
             "status": "PREFLIGHT"}
    save(output / "e2e-state.json", state)
    try:
        async with async_session() as db, db.begin():
            identity = (await db.execute(text("select current_database(), current_user"))).one()
            require(identity[0] == f"gade_{run_id}_fresh" and identity[1] == identity[0], "PostgreSQL identity mismatch")
            for model in (Target, ToolTask, ToolResult):
                count = (await db.execute(select(func.count()).select_from(model))).scalar_one()
                require(count == 0, f"isolated database contains {model.__tablename__} rows")
            registry = (await db.execute(select(ToolRegistry).where(ToolRegistry.tool_name == TOOL))).scalar_one_or_none()
            action = (await db.execute(select(ValidationAction).where(ValidationAction.action_id == ACTION))).scalar_one_or_none()
            template = (await db.execute(select(CommandTemplate).where(CommandTemplate.template_id == ACTION_TEMPLATES[ACTION]))).scalar_one_or_none()
            require(registry is not None and registry.enabled, "ToolRegistry missing or disabled")
            require(action is not None and action.enabled and action.validation_tier == 1, "L1 ValidationAction missing or disabled")
            require(action.tool_name == TOOL and action.execution_identity == ACTION_IDENTITIES[ACTION], "Action identity drift")
            require(action.template_version == ACTION_TEMPLATES[ACTION], "Action template version drift")
            require(template is not None and template.enabled and template.tool_name == TOOL, "CommandTemplate missing or disabled")
            require(template.argv_template[0] == "builtin:http-security-headers", "unexpected command template")
            state["registry"] = {"tool_id": registry.id, "enabled": registry.enabled,
                                 "action_id": action.id, "template_id": template.id,
                                 "template_version": template.template_id}
            state["status"] = "GOVERNANCE_PREFLIGHT_PASS"
            save(output / "e2e-state.json", state)

        async with async_session() as db, db.begin():
            target = Target(target=TARGET, target_type="ip", scope=SCOPE,
                            authorization_depth=1, authorization_policy_version=POLICY_VERSION,
                            authorization_configured_by="gade-l1-isolated-runner", status="pending",
                            current_round=1, max_round=1)
            db.add(target)
            await db.flush()
            port = OpenPort(target_id=target.id, ip=TARGET, port=PORT, protocol="tcp", service="http", state="open")
            db.add(port)
            await db.flush()
            refs = context_evidence(target, port)
            params = canonical_parameters(target=TARGET, port=PORT, protocol="tcp", service="http", action_id=ACTION)
            require(params["target"] == TARGET and params["port"] == PORT and params["scheme"] == "http", "canonical endpoint drift")
            governed = await evaluate_and_authorize(
                db, target=target, tool_name=TOOL, parameters=params,
                reason="One bounded HEAD request to the authorized isolated Lab",
                confidence=None, provider="deterministic-l1-lab", authorization_source="gade-tier-policy",
                raw_proposal={"selected_action": ACTION, "proposed_parameters": params,
                              "source": "deterministic-l1-lab",
                              "experiment_correlation_id": correlation_id},
                evidence_refs=refs)
            require(governed.evaluation is not None and governed.evaluation.outcome == "ALLOW", "authorization decision was not ALLOW")
            require(governed.authorization is not None, "no executable grant")
            grant = governed.authorization
            require(grant.canonical_parameters == params and grant.scope == SCOPE, "grant scope or parameters drift")
            task, inserted = await create_tool_task_if_not_exists(
                db, target_id=target.id, open_port_id=port.id, tool_name=TOOL,
                status="pending", priority=5, approval_required=False, approval_status="not_required",
                proposal_reason="Deterministic isolated L1 Lab validation",
                investigation_id=governed.proposal.investigation_id,
                action_id=ACTION, execution_authorization_id=grant.id)
            require(inserted and task is not None, "task insert failed or deduplicated")
            state["ids"] = {"target_id": target.id, "open_port_id": port.id,
                            "proposal_id": governed.proposal.id, "decision_id": governed.evaluation.id,
                            "authorization_id": grant.id, "tool_task_id": task.id,
                            "investigation_id": governed.proposal.investigation_id}
            state["evidence"] = refs
            state["canonical_parameters"] = params
            state["decision"] = row_dict(governed.evaluation)
            state["grant"] = row_dict(grant)
            state["status"] = "AUTHORIZED_TASK_CREATED"
            save(output / "e2e-state.json", state)

        task_id = state["ids"]["tool_task_id"]
        state["phase"] = "SINGLE_TASK_GOVERNANCE_AND_WORKER"
        state["request_id"] = None
        state["experiment_correlation_id"] = os.environ.get("GADE_L1_CORRELATION_ID")
        save(output / "e2e-state.json", state)
        await execute_task(task_id)  # exact task only; never poll_once/poll_target_once
        async with async_session() as db:
            result = (await db.execute(select(ToolResult).where(ToolResult.tool_task_id == task_id))).scalar_one_or_none()
            task = await db.get(ToolTask, task_id)
            result_count = (await db.execute(select(func.count()).select_from(ToolResult))).scalar_one()
            require(result is not None, "Worker path produced no ToolResult")
            trace = await trace_tool_result(db, result.id)
            state["worker_request"] = task.execution_request
            state["worker_request_hash"] = task.execution_request_hash
            state["request_id"] = ((task.execution_request or {}).get("request_id"))
            state["experiment_correlation_id"] = ((task.execution_request or {}).get("correlation_id"))
            state["execution_audit"] = task.execution_audit
            state["worker_exchange"] = (task.execution_audit or {}).get("worker_exchange")
            state["worker_receipt"] = result.execution_receipt
            state["tool_result"] = row_dict(result)
            state["tool_result_persisted_observed_utc"] = datetime.now(timezone.utc).isoformat()
            state["trace"] = trace
            state["trace_id"] = result.id
            receipt = result.execution_receipt or {}
            parsed = result.parsed_output or {}
            require(result_count == 1, "isolated run produced more than one ToolResult")
            require(task.status == "completed", "ToolTask did not complete")
            require(task.execution_request is not None, "Worker request missing")
            require(task.execution_request.get("target") == TARGET and task.execution_request.get("port") == PORT,
                    "Worker request target/port drift")
            if state["api_mode"] == "legacy":
                exchange = state.get("worker_exchange") or {}
                require(exchange.get("api_mode") == "legacy", "Legacy Worker exchange was not recorded")
                require(exchange.get("native_receipt_status") == "NATIVE_WORKER_RECEIPT_UNAVAILABLE",
                        "Legacy receipt limitation was not recorded")
                require(exchange.get("request_id") == task.execution_request.get("request_id")
                        and exchange.get("correlation_id") == state["experiment_correlation_id"]
                        and exchange.get("task_id") == task_id
                        and exchange.get("authorization_id") == state["ids"]["authorization_id"],
                        "Local legacy correlation mapping mismatch")
                require(exchange.get("http_request", {}).get("body") == {
                    "tool": TOOL, "target": TARGET, "port": PORT, "service": "http",
                }, "Legacy Worker request exceeded the fixed Action Contract")
                require(trace["status"] == "PARTIAL"
                        and "native_worker_receipt_unavailable" in trace["issues"],
                        "Legacy Worker without a receipt must remain PARTIAL")
                state["status"] = "LEGACY_L1_GOVERNANCE_PATH_RECORDED"
                state["tool_execution_success_reported_by_worker"] = bool(result.success)
                if result.success:
                    require(parsed.get("status_code") == 200
                            or (parsed.get("parsed_result") or {}).get("status_code") == 200,
                            "Expected Lab HTTP 200 missing from parsed ToolResult")
                state["completed_utc"] = datetime.now(timezone.utc).isoformat()
                state["task_status"] = task.status
                state["task_status_observed_utc"] = datetime.now(timezone.utc).isoformat()
                save(output / "e2e-state.json", state)
                print("LEGACY_L1_GOVERNANCE_PATH=RECORDED RESULT_ID=" + str(result.id))
            else:
                require(receipt.get("handler_invoked") is True, "Worker handler invocation not verified")
                require(receipt.get("task_id") == task_id and
                        receipt.get("authorization_id") == state["ids"]["authorization_id"] and
                        receipt.get("executed_action") == ACTION, "Worker receipt authority mismatch")
                require(receipt.get("executed_parameters") == state["canonical_parameters"], "Worker parameter drift")
                require(receipt.get("request_hash") == task.execution_request_hash, "Worker request hash mismatch")
                expected_worker_build = hashlib.sha256((ROOT / "kali_worker" / "app.py").read_bytes()).hexdigest()
                require(task.execution_request.get("expected_worker_build_sha256") == expected_worker_build,
                        "Worker request expected-build hash differs from Repository source")
                require(receipt.get("worker_build_sha256") == expected_worker_build,
                        "Worker build hash differs from the Repository source")
                require(result.success is True, "Worker ToolResult was not successful")
                require(parsed.get("status_code") == 200 or (parsed.get("parsed_result") or {}).get("status_code") == 200,
                        "Lab HTTP 200 missing from ToolResult")
                require(trace["status"] == "COMPLETE" and not trace["issues"], "Execution Trace incomplete")
                state["status"] = "REAL_WORKER_L1_E2E_PASS"
            state["completed_utc"] = datetime.now(timezone.utc).isoformat()
            save(output / "e2e-state.json", state)
            if state["api_mode"] != "legacy":
                print("REAL_WORKER_L1_E2E=PASS RESULT_ID=" + str(result.id))
    except BaseException as exc:
        state["status"] = "FAIL"
        state["error"] = f"{type(exc).__name__}: {exc}"
        try:
            failed_task_id = state.get("ids", {}).get("tool_task_id")
            if failed_task_id is not None:
                async with async_session() as db:
                    failed_task = await db.get(ToolTask, failed_task_id)
                    if failed_task is not None:
                        state["worker_request"] = failed_task.execution_request
                        state["worker_request_hash"] = failed_task.execution_request_hash
                        state["request_id"] = (failed_task.execution_request or {}).get("request_id")
                        state["execution_audit"] = failed_task.execution_audit
                        state["worker_exchange"] = (failed_task.execution_audit or {}).get("worker_exchange")
                    failed_result = (await db.execute(select(ToolResult).where(
                        ToolResult.tool_task_id == failed_task_id))).scalar_one_or_none()
                    if failed_result is not None:
                        state["tool_result"] = row_dict(failed_result)
                        state["tool_result_persisted_observed_utc"] = datetime.now(timezone.utc).isoformat()
                        state["trace"] = await trace_tool_result(db, failed_result.id)
                        state["trace_id"] = failed_result.id
        except Exception as diagnostic_error:
            state["failure_diagnostic_error"] = f"{type(diagnostic_error).__name__}: {diagnostic_error}"
        state["failure"] = {
            "phase": state.get("phase", "UNKNOWN"),
            "exception_type": type(exc).__name__,
            "message": str(exc),
            "traceback": traceback.format_exc(),
            "request_id": state.get("request_id") or (state.get("worker_request") or {}).get("request_id"),
        }
        state["failed_utc"] = datetime.now(timezone.utc).isoformat()
        save(output / "e2e-state.json", state)
        raise
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(run())
