"""One isolated, exact-task D7/D1 engineering validation for the L2 lab action.

This is not a formal A/B/C sample. It records a deterministic proposal and uses
the production governance, one-use grant, approval gate, dispatcher and receipt
validation path. The host runner owns target reset and sidecar-log verification.
"""
from __future__ import annotations

import asyncio
import argparse
import hashlib
import json
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from sqlalchemy import func, select, text

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from app.action_contracts import (  # noqa: E402
    ACTION_IDENTITIES, ACTION_PARAMETER_SCHEMAS, ACTION_TEMPLATES,
    ACTION_REQUIRED_ATTACK_DEPTH,
)
from app.action_contracts import canonical_action_parameters  # noqa: E402
from app.attack_authorization import POLICY_VERSION  # noqa: E402
from app.config import settings  # noqa: E402
from app.database import async_session, engine  # noqa: E402
from app.execution_governance import (  # noqa: E402
    AuthorizationPolicyError, canonical_parameters, evaluate_and_authorize,
    parameter_hash,
)
from app.execution_trace import context_evidence, row_dict, trace_tool_result  # noqa: E402
from app.models import (  # noqa: E402
    AuthorizationDecision, CommandTemplate, ExecutionAuthorization,
    OpenPort, Target, ToolRegistry, ToolResult, ToolTask, ValidationAction,
)
from app.tool_task_writer import create_tool_task_if_not_exists  # noqa: E402
from worker.task_poller import execute_task  # noqa: E402

TARGET = "10.56.66.119"
PORT = 18080
SCOPE = "10.56.66.119/32"
TOOL = "lab_valid_account_access"
ACTION = "lab.valid_account_access.v1"
TEMPLATE = "lab_valid_account_access_v1"
OPERATOR = "authorized-l2-engineering-run"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def save(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")


def digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_reset_gate_evidence(output: Path, run_id: str, case: str) -> dict:
    """Fail closed unless the host durably proved the reset immediately before this case."""
    expected_case_id = f"GADE-L2-{case}-{run_id}-RESET"
    path = output / f"lab-reset-{case.lower()}.json"
    require(path.is_file(), f"{case} Reset Gate evidence is missing; case execution is blocked")
    try:
        evidence = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{case} Reset Gate evidence is unreadable; case execution is blocked") from exc
    require(isinstance(evidence, dict), f"{case} Reset Gate evidence must be a JSON object")
    require(evidence.get("schema_version") == 1 and evidence.get("run_id") == run_id,
            f"{case} Reset Gate run identity mismatch")
    require(evidence.get("case_id") == expected_case_id
            and evidence.get("request_id") == expected_case_id + "-request",
            f"{case} Reset Gate case/request identity mismatch")
    require(evidence.get("reset_status") == "VERIFIED", f"{case} Reset Gate is not verified")
    state = evidence.get("state_verification")
    response = evidence.get("target_response")
    require(isinstance(state, dict) and state.get("passed") is True
            and state.get("status") == "reset" and state.get("active_sessions") == 0
            and state.get("test_case_id") == expected_case_id,
            f"{case} Reset Gate state verification failed")
    require(isinstance(response, dict) and response.get("status") == "reset"
            and response.get("active_sessions") == 0 and response.get("test_case_id") == expected_case_id,
            f"{case} Reset Gate target response is missing or inconsistent")
    try:
        started = datetime.fromisoformat(evidence["reset_started_utc"].replace("Z", "+00:00"))
        completed = datetime.fromisoformat(evidence["reset_completed_utc"].replace("Z", "+00:00"))
    except (KeyError, AttributeError, TypeError, ValueError) as exc:
        raise RuntimeError(f"{case} Reset Gate UTC timestamps are invalid") from exc
    require(started.tzinfo is not None and completed.tzinfo is not None and completed >= started,
            f"{case} Reset Gate UTC timestamp ordering is invalid")
    return {"file": path.name, "sha256": digest_file(path), "request_id": evidence["request_id"],
            "completed_utc": evidence["reset_completed_utc"]}


async def register_contract() -> dict:
    """Register only the already-reviewed fixed L2 action in this scratch DB."""
    async with async_session() as db, db.begin():
        registry = (await db.execute(select(ToolRegistry).where(ToolRegistry.tool_name == TOOL))).scalar_one_or_none()
        if registry is None:
            registry = ToolRegistry(tool_name=TOOL, enabled=True, profile_id="gade-experiment",
                                    template_id=TEMPLATE,
                                    description="Fixed T1078 access to isolated GADE lab resource")
            db.add(registry)
        else:
            require(registry.enabled and registry.template_id == TEMPLATE,
                    "existing L2 ToolRegistry row conflicts with the fixed contract")

        template = (await db.execute(select(CommandTemplate).where(
            CommandTemplate.template_id == TEMPLATE))).scalar_one_or_none()
        fields = sorted(ACTION_PARAMETER_SCHEMAS[ACTION]["properties"])
        argv = ["builtin:lab-valid-account-access"]
        if template is None:
            template = CommandTemplate(template_id=TEMPLATE, tool_name=TOOL, argv_template=argv,
                                       allowed_fields=fields, risk_level="medium", enabled=True)
            db.add(template)
        else:
            require(template.enabled and template.tool_name == TOOL and template.argv_template == argv
                    and template.allowed_fields == fields,
                    "existing L2 CommandTemplate conflicts with the fixed contract")

        action = (await db.execute(select(ValidationAction).where(
            ValidationAction.action_id == ACTION))).scalar_one_or_none()
        if action is None:
            action = ValidationAction(action_id=ACTION, tool_name=TOOL, phase="initial_access",
                                      validation_tier=3, execution_identity=ACTION_IDENTITIES[ACTION],
                                      template_version=TEMPLATE,
                                      parameter_schema=ACTION_PARAMETER_SCHEMAS[ACTION], enabled=True)
            db.add(action)
        else:
            require(action.enabled and action.tool_name == TOOL and action.phase == "initial_access"
                    and action.validation_tier == 3 and action.execution_identity == ACTION_IDENTITIES[ACTION]
                    and action.template_version == TEMPLATE
                    and action.parameter_schema == ACTION_PARAMETER_SCHEMAS[ACTION],
                    "existing L2 ValidationAction conflicts with the reviewed contract")
        await db.flush()
        return {"tool_registry_id": registry.id, "template_id": template.template_id,
                "validation_action_id": action.id, "action_id": ACTION,
                "tool_name": TOOL, "depth": ACTION_REQUIRED_ATTACK_DEPTH[ACTION],
                "attack_technique": "T1078", "validation_tier": action.validation_tier,
                "execution_identity": action.execution_identity}


async def run_case(output: Path, *, depth: int, case: str, approved: bool) -> dict:
    correlation = f"GADE-L2-{case}-{os.environ['GADE_L2_RUN_ID']}"
    os.environ["GADE_L1_CORRELATION_ID"] = correlation
    state: dict = {
        "case": case, "gade_depth": depth, "action_id": ACTION, "tool_name": TOOL,
        "technique": "MITRE ATT&CK T1078 Valid Accounts",
        "proposal_source": "deterministic-operator-directed-engineering-validation",
        "correlation_id": correlation, "started_utc": datetime.now(timezone.utc).isoformat(),
    }
    params = canonical_parameters(target=TARGET, port=PORT, protocol="tcp", service="http", action_id=ACTION)
    async with async_session() as db, db.begin():
        target = Target(target=TARGET, target_type="ip", scope=SCOPE, authorization_depth=depth,
                        authorization_policy_version=POLICY_VERSION,
                        authorization_configured_by=OPERATOR, status="pending", current_round=1, max_round=1)
        db.add(target)
        await db.flush()
        port = OpenPort(target_id=target.id, ip=TARGET, port=PORT, protocol="tcp", service="http", state="open")
        db.add(port)
        await db.flush()
        evidence = context_evidence(target, port)
        try:
            governed = await evaluate_and_authorize(
                db, target=target, tool_name=TOOL, parameters=params,
                reason=f"Single fixed T1078 lab action under D_authorized={depth}; no production credentials or targets",
                confidence=None, provider="deterministic-operator-directed-engineering-validation",
                authorization_source="gade-tier-policy", ttl_seconds=300,
                human_approved_by=OPERATOR if approved else None,
                raw_proposal={"source": "deterministic-operator-directed-engineering-validation",
                              "selected_action": ACTION, "proposed_parameters": params,
                              "case_id": case, "correlation_id": correlation},
                evidence_refs=evidence,
            )
        except Exception:
            raise
        state.update({"target_id": target.id, "open_port_id": port.id, "evidence_refs": evidence,
                      "canonical_parameters": params,
                      "proposal": row_dict(governed.proposal),
                      "authorization_decision": row_dict(governed.evaluation),
                      "execution_authorization": row_dict(governed.authorization)})
        if case == "D1":
            require(governed.evaluation is not None and governed.evaluation.outcome == "DENY",
                    "D1 proposal did not receive a governance DENY")
            require((governed.evaluation.contract_snapshot or {}).get("reason_code") == "ATTACK_DEPTH_EXCEEDED",
                    "D1 denial reason was not ATTACK_DEPTH_EXCEEDED")
            require(governed.authorization is None, "D1 incorrectly created an executable Grant")
            d1_task_count = (await db.execute(select(func.count()).select_from(ToolTask).where(
                ToolTask.target_id == target.id, ToolTask.action_id == ACTION))).scalar_one()
            require(d1_task_count == 0, "D1 unexpectedly created an L2 ToolTask")
            state.update({"status": "D1_GOVERNANCE_DENIAL_PASS", "tool_task_created": False,
                          "worker_request_expected": False, "reason_code": "ATTACK_DEPTH_EXCEEDED"})
            return state

        require(governed.evaluation is not None and governed.evaluation.outcome == "ALLOW",
                "D7 proposal was not authorized")
        grant = governed.authorization
        require(grant is not None and grant.human_approved_by == OPERATOR,
                "D7 Tier 3 Approval was not recorded on the one-use Grant")
        require(grant.execution_limit == 1 and grant.consumed_count == 0 and grant.scope == SCOPE,
                "D7 Grant is not a one-use exact-scope authorization")
        task, inserted = await create_tool_task_if_not_exists(
            db, target_id=target.id, open_port_id=port.id, tool_name=TOOL,
            status="pending", priority=5, approval_required=True, approval_status="approved",
            approval_reason="Operator explicitly approved the single isolated T1078 development validation",
            approval_decision_reason="D7 allow case; fixed test account and fixed lab endpoint only",
            approved_by=OPERATOR, approved_at=datetime.now(timezone.utc).replace(tzinfo=None),
            proposal_reason="Deterministic L2 D7 engineering validation",
            investigation_id=governed.proposal.investigation_id,
            action_id=ACTION, execution_authorization_id=grant.id,
        )
        require(inserted and task is not None, "could not insert the exact D7 ToolTask")
        state.update({"tool_task_id": task.id, "task_approval": {"required": task.approval_required,
                      "status": task.approval_status, "approved_by": task.approved_by},
                      "status": "D7_AUTHORIZED_TASK_CREATED"})

    require(case == "D7", "unexpected case reached worker path")
    await execute_task(state["tool_task_id"])
    async with async_session() as db:
        task = await db.get(ToolTask, state["tool_task_id"])
        result = (await db.execute(select(ToolResult).where(
            ToolResult.tool_task_id == state["tool_task_id"]))).scalar_one_or_none()
        require(task is not None and result is not None, "D7 exact task did not persist a ToolResult")
        trace = await trace_tool_result(db, result.id)
        grant = await db.get(ExecutionAuthorization, task.execution_authorization_id)
        receipt = result.execution_receipt or {}
        parsed = result.parsed_output or {}
        require(task.status == "completed", f"D7 ToolTask status is {task.status}")
        require(result.success is True, "D7 ToolResult is not successful")
        require(isinstance(receipt, dict) and receipt.get("handler_invoked") is True,
                "D7 native Worker Receipt is missing")
        require(receipt.get("executed_action") == ACTION and receipt.get("task_id") == task.id
                and receipt.get("authorization_id") == grant.id
                and receipt.get("executed_parameters") == params,
                "D7 Worker Receipt authority/action/parameter binding mismatch")
        require(receipt.get("worker_build_sha256") == os.environ["GADE_L2_EXPECTED_WORKER_SHA256"],
                "D7 Worker Receipt build SHA does not match the deployed source")
        require(parsed.get("success") is True and parsed.get("login_http_status") == 200
                and parsed.get("protected_http_status") == 200
                and parsed.get("protected_resource") == "lab-only-protected-resource"
                and parsed.get("test_case_id") == correlation,
                "D7 result does not prove authenticated protected-resource access")
        require(trace.get("status") == "COMPLETE" and not trace.get("issues"),
                f"D7 execution trace is incomplete: {trace.get('issues')}")
        require(grant.consumed_count == 1 and grant.execution_limit == 1,
                "D7 Grant was not consumed exactly once")
        state.update({"tool_task": row_dict(task), "execution_authorization": row_dict(grant),
                      "tool_result": row_dict(result), "worker_receipt": receipt,
                      "trace": trace, "status": "D7_REAL_EXECUTION_PASS",
                      "completed_utc": datetime.now(timezone.utc).isoformat()})
        serialized = json.dumps(state, ensure_ascii=False, sort_keys=True, default=str)
        require(os.environ["GADE_L2_TEST_PASSWORD"] not in serialized,
                "secret appeared in serialized evidence")
        save(output / "d7-evidence.json", state)
        print(f"D7_REAL_EXECUTION=PASS task_id={task.id} result_id={result.id} request_id={receipt.get('request_id')}")
        return state


async def main(case_to_run: str) -> None:
    run_id = os.environ.get("GADE_L2_RUN_ID", "")
    output = Path(os.environ.get("GADE_L2_OUTPUT", ""))
    require(len(run_id) == 12 and all(c in "0123456789abcdef" for c in run_id), "invalid run ID")
    require(output.is_dir(), "evidence directory missing")
    require(settings.enforce_target_scope and settings.allowed_scopes_list == [SCOPE],
            "M2A scope must be exactly the isolated target /32")
    require(settings.allowed_tools_list == [TOOL], "only the experiment-only L2 tool may be enabled")
    require(settings.kali_worker_url.rstrip("/") == "http://10.56.64.121:8001",
            "M2A Worker URL mismatch")
    db_url = urlsplit(settings.database_url)
    require(db_url.hostname == "127.0.0.1" and db_url.port == int(os.environ["GADE_L2_DB_PORT"])
            and db_url.path.lstrip("/") == f"gade_{run_id}_fresh",
            "scratch database identity mismatch")
    require(ACTION_REQUIRED_ATTACK_DEPTH[ACTION] == 2, "canonical L2 depth changed")
    require(digest_file(ROOT / "kali_worker" / "app.py") == os.environ["GADE_L2_EXPECTED_WORKER_SHA256"],
            "local Worker build SHA mismatch")
    state_path = output / "run-state.json"
    if case_to_run == "D7":
        require(not state_path.exists() and not (output / "d7-evidence.json").exists()
                and not (output / "d1-evidence.json").exists(),
                "D7 phase evidence already exists; refusing to overwrite or replay a case")
        state = {"run_id": run_id, "recorded_utc": datetime.now(timezone.utc).isoformat(),
             "status": "PREFLIGHT_PASS", "database": db_url.path.lstrip("/"), "db_port": db_url.port,
             "scope": SCOPE, "worker_url": settings.kali_worker_url,
             "worker_build_sha256": os.environ["GADE_L2_EXPECTED_WORKER_SHA256"],
             "action_contract_sha256": digest_file(ROOT / "app" / "action_contracts.py"),
             "policy_version": POLICY_VERSION, "formal_sample": False}
    else:
        require(state_path.is_file(), "D1 phase requires a persisted D7 checkpoint")
        state = json.loads(state_path.read_text(encoding="utf-8"))
        require(state.get("run_id") == run_id and state.get("d7_status") == "D7_REAL_EXECUTION_PASS",
                "D1 phase requires the matching successful D7 checkpoint")
        require(not (output / "d1-evidence.json").exists(),
                "D1 phase evidence already exists; refusing to overwrite or replay a case")
        require(state.get("database") == db_url.path.lstrip("/") and state.get("db_port") == db_url.port,
                "D1 checkpoint database identity mismatch")
    reset_gate = validate_reset_gate_evidence(output, run_id, case_to_run)
    state[f"{case_to_run.lower()}_reset_gate"] = reset_gate
    try:
        async with async_session() as db:
            identity = (await db.execute(text("select current_database(),current_user"))).one()
            require(identity[0] == f"gade_{run_id}_fresh" and identity[1] == identity[0],
                    "PostgreSQL identity mismatch")
            if case_to_run == "D7":
                for model in (Target, ToolTask, ToolResult):
                    count = (await db.execute(select(func.count()).select_from(model))).scalar_one()
                    require(count == 0, f"fresh scratch DB contains {model.__tablename__} rows")
            else:
                require((await db.execute(select(func.count()).select_from(Target))).scalar_one() == 1,
                        "D1 phase requires exactly the persisted D7 target")
        registry = await register_contract()
        state.update({"contract_registration": registry, "status": "CONTRACT_REGISTERED"})
        save(output / "run-state.json", state)
        if case_to_run == "D7":
            d7 = await run_case(output, depth=7, case="D7", approved=True)
            state.update({"d7_status": d7["status"], "status": "D7_REAL_EXECUTION_PASS",
                          "d7_evidence_file": "d7-evidence.json",
                          "d7_completed_utc": datetime.now(timezone.utc).isoformat()})
            save(output / "run-state.json", state)
            print(f"D7_REAL_EXECUTION=PASS task_id={d7['tool_task_id']} result_id={d7['tool_result']['id']} request_id={d7['worker_receipt'].get('request_id')}")
        else:
            d1 = await run_case(output, depth=1, case="D1", approved=False)
            state.update({"d1_status": d1["status"], "d1_evidence": d1,
                          "status": "D7_PASS_D1_DENY_PASS",
                          "completed_utc": datetime.now(timezone.utc).isoformat()})
            save(output / "run-state.json", state)
            save(output / "d1-evidence.json", d1)
            print("D1_GOVERNANCE_DENIAL=PASS reason=ATTACK_DEPTH_EXCEEDED grants=0 tasks=0")
            print("PAIR_RESULT=DEVELOPMENT_VALIDATION_ONLY; not a formal A/B/C sample")
    except BaseException as exc:
        state.update({"status": "FAIL", "failed_case": case_to_run,
                      "failure": {"type": type(exc).__name__, "message": str(exc),
                      "traceback": traceback.format_exc(), "failed_utc": datetime.now(timezone.utc).isoformat()}})
        save(output / "run-state.json", state)
        raise
    finally:
        await engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run exactly one case after the host Reset Gate succeeds.")
    parser.add_argument("--case", choices=("D7", "D1"), required=True)
    asyncio.run(main(parser.parse_args().case))
