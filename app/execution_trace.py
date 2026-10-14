"""Evidence snapshots and read-only reconstruction; no tool execution."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import Any

from sqlalchemy import select

from app.execution_governance import parameter_hash
from app.models import (AuthorizationDecision, DecisionProposal, DecisionScore,
                        ExecutionAuthorization, ToolResult, ToolTask)


def evidence_ref(reference: str, content: dict, kind: str = "input_snapshot") -> dict:
    content = deepcopy(content)
    digest = parameter_hash(content)
    return {"reference": reference, "evidence_id": f"sha256:{digest}",
            "type": kind, "sha256": digest, "content": content}


def context_evidence(target, port=None, decision=None) -> list[dict]:
    """Freeze exactly the objects used by the caller; never infer old inputs."""
    refs = [evidence_ref(f"targets:{target.id}",
                        {"target": target.target, "scope": target.scope}, "registered_target")]
    if port is not None and getattr(port, "id", None) is not None:
        refs.append(evidence_ref(f"open_ports:{port.id}", {
            key: getattr(port, key, None) for key in
            ("target_id", "port", "protocol", "service", "scan_run_id", "product", "version")
        }, "service_evidence"))
    if decision is not None:
        refs.append(evidence_ref(f"decision_scores:{decision.id}", {
            "input_snapshot": decision.input_snapshot,
            "next_action": decision.next_action, "next_tool": decision.next_tool,
            "reason": decision.reason,
        }, "decision_input"))
    return refs


def proposal_input(row) -> dict:
    return {key: getattr(row, key, None) for key in
            ("target_id", "investigation_id", "action_id", "canonical_parameters",
             "decision_score_id", "raw_proposal", "evidence_refs", "provider", "reason")}


def grant_contract(row) -> dict:
    return {key: (value.isoformat() if isinstance(value, datetime) else deepcopy(value))
            for key in ("id", "proposal_id", "target_id", "investigation_id", "action_id",
                        "canonical_parameters", "parameters_hash", "execution_identity",
                        "template_version", "validation_tier", "scope", "execution_limit",
                        "expires_at", "authorization_source")
            for value in [getattr(row, key, None)]}


def evaluation_matches_grant(evaluation, grant) -> bool:
    """Check the authorization snapshot's grant fields, allowing policy metadata.

    AuthorizationDecision.contract_snapshot also stores policy checks and a reason
    code. Comparing that entire object to the grant contract incorrectly marks every
    otherwise valid evaluation as mismatched.
    """
    snapshot = evaluation.contract_snapshot
    if not isinstance(snapshot, dict):
        return False
    expected = grant_contract(grant)
    return all(key in snapshot and snapshot[key] == value for key, value in expected.items())


def evaluation_input(row) -> dict:
    return {key: getattr(row, key, None) for key in
            ("proposal_id", "authorization_id", "outcome", "reason", "policy_source", "contract_snapshot")}


def result_output(row) -> dict:
    return {key: getattr(row, key, None) for key in
            ("tool_task_id", "action_id", "tool_name", "command", "raw_output",
             "parsed_output", "success", "execution_receipt")}


def execution_request(ctx) -> dict:
    return {"tool": ctx.tool_name, "target": ctx.host, "port": ctx.port,
            "protocol": ctx.protocol, "service": ctx.service, "action_id": ctx.action_id,
            "execution_identity": ctx.execution_identity,
            "authorization_parameters": deepcopy(ctx.authorization_parameters),
            "authorization_parameters_hash": ctx.authorization_parameters_hash,
            "task_id": ctx.task_id, "authorization_id": getattr(ctx, "authorization_id", None),
            "request_id": getattr(ctx, "request_id", None),
            "correlation_id": getattr(ctx, "correlation_id", None),
            "template_id": getattr(ctx, "template_id", None),
            "expected_worker_build_sha256": getattr(ctx, "expected_worker_build_sha256", None)}


def row_dict(row) -> dict | None:
    if row is None:
        return None
    return {column.name: (value.isoformat() if isinstance(value, datetime) else deepcopy(value))
            for column in row.__table__.columns for value in [getattr(row, column.name)]}


async def trace_tool_result(db, result_id: int) -> dict[str, Any]:
    """Missing historical edges and mismatches remain explicit, never repaired."""
    issues = []
    result = await db.get(ToolResult, result_id)
    if result is None:
        return {"status": "NOT_FOUND", "result_id": result_id, "issues": ["tool_result_missing"]}
    task = await db.get(ToolTask, result.tool_task_id) if result.tool_task_id else None
    grant = await db.get(ExecutionAuthorization, task.execution_authorization_id) if task and task.execution_authorization_id else None
    proposal = await db.get(DecisionProposal, grant.proposal_id) if grant else None
    evaluation = (await db.execute(select(AuthorizationDecision).where(
        AuthorizationDecision.authorization_id == grant.id))).scalar_one_or_none() if grant else None
    for name, row in (("tool_task", task), ("execution_authorization", grant),
                      ("decision", proposal), ("authorization_decision", evaluation)):
        if row is None:
            issues.append(f"{name}_missing")
    refs = (proposal.evidence_refs or []) if proposal else []
    if not refs:
        issues.append("evidence_missing")
    for ref in refs:
        if (not isinstance(ref, dict) or not ref.get("reference")
                or not isinstance(ref.get("content"), dict)
                or ref.get("sha256") != parameter_hash(ref["content"])
                or ref.get("evidence_id") != f"sha256:{ref.get('sha256')}"):
            issues.append("evidence_integrity_mismatch")
    if proposal:
        if not proposal.raw_proposal:
            issues.append("raw_proposal_missing")
        if not proposal.input_hash or proposal.input_hash != parameter_hash(proposal_input(proposal)):
            issues.append("proposal_integrity_unverified")
    if grant and grant.parameters_hash != parameter_hash(grant.canonical_parameters):
        issues.append("authorization_parameters_mismatch")
    if proposal and grant and (grant.target_id != proposal.target_id
                               or grant.investigation_id != proposal.investigation_id
                               or grant.action_id != proposal.action_id):
        issues.append("proposal_authorization_identity_mismatch")
    if evaluation:
        if (evaluation.outcome != "ALLOW" or evaluation.proposal_id != grant.proposal_id
                or not evaluation_matches_grant(evaluation, grant)
                or evaluation.record_hash != parameter_hash(evaluation_input(evaluation))):
            issues.append("authorization_evaluation_mismatch")
    if task:
        if not task.execution_request or task.execution_request_hash != parameter_hash(task.execution_request):
            issues.append("execution_request_unverified")
        elif grant and (not task.execution_request.get("request_id")
                        or not task.execution_request.get("template_id")
                        or not task.execution_request.get("expected_worker_build_sha256")):
            issues.append("execution_request_correlation_missing")
        elif grant and (task.execution_request.get("task_id") != task.id
                        or task.execution_request.get("authorization_id") != grant.id
                        or task.execution_request.get("action_id") != grant.action_id
                        or task.execution_request.get("authorization_parameters") != grant.canonical_parameters
                        or task.execution_request.get("authorization_parameters_hash") != grant.parameters_hash
                        or task.execution_request.get("execution_identity") != grant.execution_identity):
            issues.append("authorization_request_mismatch")
        if grant and (task.target_id != grant.target_id or task.action_id != grant.action_id
                      or task.investigation_id != grant.investigation_id):
            issues.append("task_authorization_identity_mismatch")
        if result.target_id != task.target_id or result.action_id != task.action_id or result.investigation_id != task.investigation_id:
            issues.append("result_task_identity_mismatch")
    receipt = result.execution_receipt
    exchange = (task.execution_audit or {}).get("worker_exchange") if task else None
    legacy_exchange = isinstance(exchange, dict) and exchange.get("api_mode") == "legacy"
    if not receipt:
        issues.append("native_worker_receipt_unavailable" if legacy_exchange else "worker_receipt_missing")
        if legacy_exchange:
            legacy_request = exchange.get("http_request")
            legacy_body = legacy_request.get("body") if isinstance(legacy_request, dict) else None
            grant_parameters = grant.canonical_parameters if grant else {}
            if (exchange.get("native_receipt_status") != "NATIVE_WORKER_RECEIPT_UNAVAILABLE"
                    or exchange.get("request_id") != (task.execution_request or {}).get("request_id")
                    or exchange.get("correlation_id") != (task.execution_request or {}).get("correlation_id")
                    or exchange.get("task_id") != task.id
                    or exchange.get("authorization_id") != (grant.id if grant else None)
                    or not isinstance(legacy_body, dict)
                    or legacy_body.get("target") != grant_parameters.get("target")
                    or legacy_body.get("port") != grant_parameters.get("port")):
                issues.append("legacy_worker_correlation_mismatch")
    elif task and grant:
        if (receipt.get("request_hash") != task.execution_request_hash
                or receipt.get("request_id") != task.execution_request.get("request_id")
                or receipt.get("correlation_id") != task.execution_request.get("correlation_id")
                or receipt.get("template_id") != task.execution_request.get("template_id")
                or receipt.get("task_id") != task.id or receipt.get("authorization_id") != grant.id
                or receipt.get("executed_action") != grant.action_id
                or receipt.get("executed_parameters") != grant.canonical_parameters
                or receipt.get("execution_identity") != grant.execution_identity
                or receipt.get("handler_invoked") is not True
                or not receipt.get("request_received_at_utc")
                or not receipt.get("handler_started_at_utc")
                or not receipt.get("handler_completed_at_utc")
                or not isinstance(receipt.get("worker_build_sha256"), str)
                or len(receipt.get("worker_build_sha256", "")) != 64
                or receipt.get("worker_build_sha256") != task.execution_request.get("expected_worker_build_sha256")
                or not receipt.get("execution_outcome")
                or receipt.get("execution_kind") not in ("subprocess", "builtin_handler")
                or (receipt.get("execution_kind") == "subprocess"
                    and receipt.get("subprocess_started") is True
                    and (not receipt.get("process_started_at_utc")
                         or not receipt.get("process_completed_at_utc")
                         or receipt.get("process_exit_code") is None
                         or not receipt.get("process_output_sha256")))):
            issues.append("authority_execution_mismatch")
    if not result.output_hash or result.output_hash != parameter_hash(result_output(result)):
        issues.append("result_integrity_unverified")
    return {"status": "PARTIAL" if issues else "COMPLETE", "issues": issues,
            "tool_result": row_dict(result), "tool_task": row_dict(task),
            "execution_authorization": row_dict(grant), "authorization_decision": row_dict(evaluation),
            "decision": row_dict(proposal), "evidence": refs,
            "native_worker_receipt_status": ("NATIVE_WORKER_RECEIPT_UNAVAILABLE" if legacy_exchange
                                              else ("PRESENT" if receipt else "MISSING")),
            "proposal_to_authority_drift": (
                proposal.raw_proposal.get("proposed_parameters") != grant.canonical_parameters
                if proposal and grant and proposal.raw_proposal and "proposed_parameters" in proposal.raw_proposal else None),
            "receipt_scope": ("Legacy response locally correlated; native handler/process attestation unavailable"
                              if legacy_exchange else
                              "Worker-reported handler invocation; not authenticated transport or destination attestation")}
