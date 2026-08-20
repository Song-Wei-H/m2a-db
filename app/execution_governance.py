from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import DecisionProposal, ExecutionAuthorization, Target, ValidationAction

ACTION_BY_TOOL = {
    "http_security_headers": "http_security_headers.collect.v1",
    "nuclei_safe": "nuclei.safe_scan.v1",
}
PROTECTED_VALIDATION_TOOLS = {"nuclei_safe"}


def utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def canonical_parameters(*, target: str, port: int | None, protocol: str | None, service: str | None) -> dict[str, Any]:
    return {"port": port, "protocol": protocol or None, "service": service or None, "target": target.strip()}


def parameter_hash(parameters: dict[str, Any]) -> str:
    payload = json.dumps(parameters, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True)
class GovernedAuthorization:
    proposal: DecisionProposal
    authorization: ExecutionAuthorization | None
    action: ValidationAction


async def propose_and_authorize(
    db: AsyncSession, *, target: Target, tool_name: str, parameters: dict[str, Any],
    reason: str, confidence: float | None, provider: str, authorization_source: str,
    investigation_id: str | None = None, human_approved_by: str | None = None,
    ttl_seconds: int = 900,
) -> GovernedAuthorization:
    action_id = ACTION_BY_TOOL.get(tool_name)
    if action_id is None:
        raise ValueError(f"Tool {tool_name!r} is pending authorization migration")
    action = (await db.execute(select(ValidationAction).where(
        ValidationAction.action_id == action_id, ValidationAction.enabled.is_(True)
    ).limit(1))).scalar_one_or_none()
    if action is None:
        raise ValueError(f"Validation action {action_id!r} is not enabled")
    expected = canonical_parameters(target=target.target, port=parameters.get("port"),
                                    protocol=parameters.get("protocol"), service=parameters.get("service"))
    if expected != parameters:
        raise ValueError("Parameters are not canonical or target binding does not match")
    investigation_id = investigation_id or f"inv-{target.id}-{uuid4().hex[:16]}"
    proposal = DecisionProposal(investigation_id=investigation_id, target_id=target.id,
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
