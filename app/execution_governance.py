from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuthorizationDecision, DecisionProposal, ExecutionAuthorization, Target, ValidationAction
from app.action_contracts import (ACTION_BY_TOOL, ACTION_IDENTITIES, ACTION_TEMPLATES,
                                  ACTION_REQUIRED_ATTACK_DEPTH, canonical_action_parameters,
                                  PROTECTED_ACTION_TOOLS)
from app.attack_authorization import POLICY_VERSION, depth_decision

PROTECTED_VALIDATION_TOOLS = PROTECTED_ACTION_TOOLS


def utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def canonical_parameters(*, target: str, port: int | None, protocol: str | None, service: str | None,
                         action_id: str | None = None) -> dict[str, Any]:
    if action_id is None:
        return {"port": port, "protocol": protocol or None, "service": service or None, "target": target.strip()}
    return canonical_action_parameters(action_id=action_id, target=target, port=port,
                                       protocol=protocol, service=service)


def parameter_hash(parameters: dict[str, Any]) -> str:
    payload = json.dumps(parameters, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True)
class GovernedAuthorization:
    proposal: DecisionProposal
    authorization: ExecutionAuthorization | None
    action: ValidationAction | None
    evaluation: AuthorizationDecision | None = None


class AuthorizationPolicyError(ValueError):
    def __init__(self, reason_code: str, message: str, snapshot: dict | None = None):
        super().__init__(message)
        self.reason_code = reason_code
        self.snapshot = snapshot or {}


async def propose_and_authorize(
    db: AsyncSession, *, target: Target, tool_name: str, parameters: dict[str, Any],
    reason: str, confidence: float | None, provider: str, authorization_source: str,
    investigation_id: str | None = None, human_approved_by: str | None = None,
    ttl_seconds: int = 900,
    _proposal: DecisionProposal | None = None,
) -> GovernedAuthorization:
    action_id = ACTION_BY_TOOL.get(tool_name)
    if action_id is None:
        raise ValueError(f"Tool {tool_name!r} is pending authorization migration")
    action = (await db.execute(select(ValidationAction).where(
        ValidationAction.action_id == action_id, ValidationAction.enabled.is_(True)
    ).limit(1))).scalar_one_or_none()
    if action is None:
        raise ValueError(f"Validation action {action_id!r} is not enabled")
    if (action.execution_identity != ACTION_IDENTITIES[action_id]
            or action.template_version != ACTION_TEMPLATES[action_id]):
        raise ValueError(f"Validation action {action_id!r} identity does not match canonical contract")
    required_depth = ACTION_REQUIRED_ATTACK_DEPTH[action_id]
    authorized_depth = getattr(target, "authorization_depth", 1) or 1
    depth_check = depth_decision(authorized_depth, required_depth)
    if not depth_check["passed"]:
        raise AuthorizationPolicyError(
            depth_check["reason_code"],
            "超出本次授權深度 (ATTACK_DEPTH_EXCEEDED)",
            {"policy_version": POLICY_VERSION, **depth_check},
        )
    profile_expires_at = getattr(target, "authorization_expires_at", None)
    if profile_expires_at is not None and profile_expires_at <= utcnow_naive():
        raise AuthorizationPolicyError(
            "ENGAGEMENT_AUTHORIZATION_EXPIRED",
            "The engagement authorization profile has expired",
            {"policy_version": POLICY_VERSION, "authorized_depth": authorized_depth,
             "required_depth": required_depth, "depth_check": "FAIL"},
        )
    expected = canonical_parameters(target=target.target, port=parameters.get("port"),
                                    protocol=parameters.get("protocol"), service=parameters.get("service"),
                                    action_id=action_id)
    if expected != parameters:
        raise ValueError("Parameters are not canonical or target binding does not match")
    investigation_id = investigation_id or f"inv-{target.id}-{uuid4().hex[:16]}"
    proposal = _proposal or DecisionProposal(investigation_id=investigation_id, target_id=target.id,
        action_id=action.action_id, canonical_parameters=parameters, confidence=confidence,
        reason=reason, provider=provider, status="proposed")
    db.add(proposal)
    await db.flush()
    if action.validation_tier == 3 and not human_approved_by:
        proposal.status = "pending_human_approval"
        return GovernedAuthorization(proposal, None, action)
    authorization = ExecutionAuthorization(proposal_id=proposal.id, investigation_id=investigation_id,
        target_id=target.id, action_id=action.action_id, canonical_parameters=parameters,
        parameters_hash=parameter_hash(parameters), execution_identity=action.execution_identity,
        template_version=action.template_version, validation_tier=action.validation_tier,
        scope=target.scope or target.target, execution_limit=1, consumed_count=0,
        expires_at=utcnow_naive() + timedelta(seconds=ttl_seconds),
        authorization_source=authorization_source, human_approved_by=human_approved_by,
        human_approved_at=utcnow_naive() if human_approved_by else None)
    db.add(authorization)
    proposal.status = "authorized"
    await db.flush()
    return GovernedAuthorization(proposal, authorization, action)


async def evaluate_and_authorize(
    db, *, target, tool_name, parameters, reason, confidence, provider,
    authorization_source, investigation_id=None, human_approved_by=None,
    ttl_seconds=900, raw_proposal=None, evidence_refs=None, decision_score_id=None,
    denial_reason=None,
) -> GovernedAuthorization:
    """Durable evaluation around the existing policy; callers commit DENY normally.

    Keep the legacy exception API above for old harnesses. Production callers use
    this service so a validation failure is not lost through transaction rollback.
    An evaluation never grants permission; only authorization is executable.
    """
    from app.execution_trace import evaluation_input, grant_contract, proposal_input
    investigation_id = investigation_id or f"inv-{target.id}-{uuid4().hex[:16]}"
    proposal = DecisionProposal(
        investigation_id=investigation_id, target_id=target.id,
        action_id=ACTION_BY_TOOL.get(tool_name, tool_name)[:150],
        canonical_parameters=deepcopy(parameters), confidence=confidence,
        reason=reason, provider=provider, status="proposed",
        raw_proposal=deepcopy(raw_proposal), evidence_refs=deepcopy(evidence_refs or []),
        decision_score_id=decision_score_id,
    )
    proposal.input_hash = parameter_hash(proposal_input(proposal))
    db.add(proposal)
    await db.flush()
    grant = action = None
    evaluation_snapshot: dict[str, Any] = {
        "policy_version": POLICY_VERSION,
        "authorized_depth": getattr(target, "authorization_depth", 1) or 1,
        "required_depth": ACTION_REQUIRED_ATTACK_DEPTH.get(ACTION_BY_TOOL.get(tool_name, "")),
        "depth_check": "PENDING",
        "evidence_check": "PENDING",
        "scope_check": "PENDING",
        "approval_check": "PENDING",
    }
    reason_code = None
    try:
        if denial_reason:
            raise AuthorizationPolicyError("PROPOSAL_INVALID", denial_reason)
        required_depth = evaluation_snapshot["required_depth"]
        depth_check = depth_decision(evaluation_snapshot["authorized_depth"], required_depth) if required_depth else {
            "passed": False, "reason_code": "ACTION_NOT_REGISTERED",
        }
        evaluation_snapshot["depth_check"] = "PASS" if depth_check["passed"] else "FAIL"
        if not depth_check["passed"]:
            raise AuthorizationPolicyError(
                depth_check["reason_code"],
                "超出本次授權深度 (ATTACK_DEPTH_EXCEEDED)" if depth_check["reason_code"] == "ATTACK_DEPTH_EXCEEDED"
                else "Action has no registered authorization depth",
                {"policy_version": POLICY_VERSION, **depth_check},
            )
        if not evidence_refs:
            proposal.status = "pending_evidence"
            outcome, detail = "PENDING", "Evidence is required before execution authorization"
            reason_code = "EVIDENCE_REQUIRED"
            evaluation_snapshot["evidence_check"] = "PENDING"
            raise AuthorizationPolicyError(reason_code, detail, evaluation_snapshot)
        for ref in evidence_refs:
            if (not isinstance(ref, dict) or not isinstance(ref.get("content"), dict)
                    or not ref.get("reference")
                    or ref.get("sha256") != parameter_hash(ref["content"])
                    or ref.get("evidence_id") != f"sha256:{ref.get('sha256')}"):
                raise AuthorizationPolicyError("EVIDENCE_INTEGRITY_FAILED", "Evidence snapshot integrity check failed",
                                               {**evaluation_snapshot, "evidence_check": "FAIL"})
        action_id = ACTION_BY_TOOL.get(tool_name)
        if action_id in {"ssh.algorithms_enum.v1", "mysql.server_info.v1"} and not any(
            isinstance(ref, dict) and ref.get("type") == "service_evidence"
            and str(ref.get("reference", "")).startswith("open_ports:")
            and ref.get("content", {}).get("target_id") == target.id
            for ref in evidence_refs
        ):
            proposal.status = "pending_evidence"
            reason_code = "SERVICE_EVIDENCE_REQUIRED"
            raise AuthorizationPolicyError(reason_code, "Service-specific evidence is required for this action",
                                           {**evaluation_snapshot, "evidence_check": "PENDING"})
        evaluation_snapshot["evidence_check"] = "PASS"
        evaluation_snapshot["scope_check"] = "PASS" if parameters.get("target") == target.target else "FAIL"
        if evaluation_snapshot["scope_check"] != "PASS":
            raise AuthorizationPolicyError("SCOPE_TARGET_MISMATCH", "Canonical action target is outside the registered target scope",
                                           evaluation_snapshot)
        result = await propose_and_authorize(
            db, target=target, tool_name=tool_name, parameters=parameters,
            reason=reason, confidence=confidence, provider=provider,
            authorization_source=authorization_source, investigation_id=investigation_id,
            human_approved_by=human_approved_by, ttl_seconds=ttl_seconds, _proposal=proposal,
        )
        grant, action = result.authorization, result.action
        outcome, detail = ("ALLOW", "canonical contract authorized") if grant else ("PENDING", "human authorization required")
        evaluation_snapshot["depth_check"] = "PASS"
        evaluation_snapshot["approval_check"] = "PASS" if grant else "PENDING"
        if grant:
            evaluation_snapshot.update({"action_id": action.action_id,
                                        "validation_tier": action.validation_tier})
    except (ValueError, KeyError, TypeError) as exc:
        reason_code = getattr(exc, "reason_code", "AUTHORIZATION_VALIDATION_FAILED")
        if reason_code in {"EVIDENCE_REQUIRED", "SERVICE_EVIDENCE_REQUIRED"}:
            outcome, detail = "PENDING", str(exc)
            proposal.status = "pending_evidence"
        else:
            outcome, detail = "DENY", str(exc)
            proposal.status = "denied"
        evaluation_snapshot.update(getattr(exc, "snapshot", {}))
        evaluation_snapshot["depth_check"] = (
            "FAIL" if reason_code in {"ATTACK_DEPTH_EXCEEDED", "ATTACK_DEPTH_INVALID"}
            else evaluation_snapshot.get("depth_check", "PENDING")
        )
        if reason_code in {"ATTACK_DEPTH_EXCEEDED", "ATTACK_DEPTH_INVALID"}:
            evaluation_snapshot["scope_check"] = "PENDING"
    evaluation = AuthorizationDecision(
        proposal_id=proposal.id, authorization_id=grant.id if grant else None,
        outcome=outcome, reason=detail, policy_source=authorization_source,
        contract_snapshot={**(grant_contract(grant) if grant else {}), **evaluation_snapshot,
                           "reason_code": reason_code},
    )
    evaluation.record_hash = parameter_hash(evaluation_input(evaluation))
    db.add(evaluation)
    await db.flush()
    return GovernedAuthorization(proposal, grant, action, evaluation)
