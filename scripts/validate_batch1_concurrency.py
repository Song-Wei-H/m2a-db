"""Real PostgreSQL single-use concurrency validation for Batch 1 TLS."""

from __future__ import annotations

import asyncio
import argparse
from datetime import timedelta

from sqlalchemy import delete, select

from app.action_contracts import ACTION_IDENTITIES, ACTION_TEMPLATES
from app.database import async_session
from app.execution_governance import canonical_parameters, parameter_hash, utcnow_naive
from app.models import DecisionProposal, ExecutionAuthorization, Target, ToolTask
from app.tool_task_constants import NOT_REQUIRED, PENDING
from worker.task_poller import _claim_task


async def main(action: str = "tls") -> None:
    proposal_id = authorization_id = task_id = None
    try:
        async with async_session() as db, db.begin():
            target = (await db.execute(select(Target).order_by(Target.id).limit(1))).scalar_one()
            config = {
                "tls": ("tls.certificate_collect.v1", "tls_certificate", 443, "tcp", "tls"),
                "nmap": ("nmap.service_fingerprint.v1", "nmap_service", None, None, None),
                "httpx": ("httpx.web_probe.v1", "httpx_basic", 80, "tcp", "http"),
            }
            action_id, tool_name, port, protocol, service = config[action]
            params = canonical_parameters(target=target.target, port=port, protocol=protocol,
                                          service=service, action_id=action_id)
            proposal = DecisionProposal(
                investigation_id=f"phase3-{action}-concurrency", target_id=target.id,
                action_id=action_id, canonical_parameters=params, confidence=1.0,
                reason="Batch 1 PostgreSQL concurrent claim validation",
                provider="integration-test", status="authorized",
            )
            db.add(proposal)
            await db.flush()
            authorization = ExecutionAuthorization(
                proposal_id=proposal.id, investigation_id=proposal.investigation_id,
                target_id=target.id, action_id=action_id, canonical_parameters=params,
                parameters_hash=parameter_hash(params),
                execution_identity=ACTION_IDENTITIES[action_id],
                template_version=ACTION_TEMPLATES[action_id], validation_tier=1,
                scope=target.scope or target.target, execution_limit=1, consumed_count=0,
                expires_at=utcnow_naive() + timedelta(minutes=5),
                authorization_source="integration-test",
            )
            db.add(authorization)
            await db.flush()
            task = ToolTask(
                target_id=target.id, tool_name=tool_name, status=PENDING,
                priority=100, approval_required=False, approval_status=NOT_REQUIRED,
                investigation_id=proposal.investigation_id, action_id=action_id,
                execution_authorization_id=authorization.id,
            )
            db.add(task)
            await db.flush()
            proposal_id, authorization_id, task_id = proposal.id, authorization.id, task.id

        async def claim() -> bool:
            async with async_session() as db, db.begin():
                return await _claim_task(db, task_id)

        outcomes = await asyncio.gather(claim(), claim())
        if sum(bool(value) for value in outcomes) != 1:
            raise AssertionError(f"expected one successful claim, got {outcomes}")
        async with async_session() as db:
            authorization = await db.get(ExecutionAuthorization, authorization_id)
            if authorization is None or authorization.consumed_count != 1:
                raise AssertionError("authorization was not consumed exactly once")
        print(f"PASS {action} concurrent claims={outcomes}; consumed_count=1")
    finally:
        if task_id is not None:
            async with async_session() as db, db.begin():
                await db.execute(delete(ToolTask).where(ToolTask.id == task_id))
                await db.execute(delete(ExecutionAuthorization).where(ExecutionAuthorization.id == authorization_id))
                await db.execute(delete(DecisionProposal).where(DecisionProposal.id == proposal_id))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", choices=("tls", "nmap", "httpx"), default="tls")
    asyncio.run(main(parser.parse_args().action))
