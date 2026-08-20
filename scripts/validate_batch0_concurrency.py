"""Real-PostgreSQL validation for atomic single-use authorization consumption."""

from __future__ import annotations

import asyncio
from datetime import timedelta

from sqlalchemy import delete, select

from app.database import async_session
from app.execution_governance import canonical_parameters, parameter_hash, utcnow_naive
from app.models import DecisionProposal, ExecutionAuthorization, Target, ToolTask
from app.tool_task_constants import NOT_REQUIRED, PENDING
from worker.task_poller import _claim_task


async def main() -> None:
    proposal_id = authorization_id = task_id = None
    try:
        async with async_session() as db, db.begin():
            target = (await db.execute(select(Target).order_by(Target.id).limit(1))).scalar_one()
            params = canonical_parameters(
                target=target.target, port=None, protocol=None, service=None,
                action_id="http_security_headers.collect.v1",
            )
            proposal = DecisionProposal(
                investigation_id="phase3-batch0-concurrency", target_id=target.id,
                action_id="http_security_headers.collect.v1", canonical_parameters=params,
                confidence=1.0, reason="PostgreSQL concurrent claim validation",
                provider="integration-test", status="authorized",
            )
            db.add(proposal)
            await db.flush()
            authorization = ExecutionAuthorization(
                proposal_id=proposal.id, investigation_id=proposal.investigation_id,
                target_id=target.id, action_id=proposal.action_id,
                canonical_parameters=params, parameters_hash=parameter_hash(params),
                execution_identity=(
                    "builtin:http-security-headers:head-root:user-agent=M2A-Worker/1:"
                    "connection=close:timeout=10:tls-verify=false:redirect=false:body=false:v2"
                ),
                template_version="http_security_headers_v2", validation_tier=1,
                scope=target.scope or target.target, execution_limit=1, consumed_count=0,
                expires_at=utcnow_naive() + timedelta(minutes=5),
                authorization_source="integration-test",
            )
            db.add(authorization)
            await db.flush()
            task = ToolTask(
                target_id=target.id, tool_name="http_security_headers", status=PENDING,
                priority=100, approval_required=False, approval_status=NOT_REQUIRED,
                investigation_id=proposal.investigation_id, action_id=proposal.action_id,
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
            raise AssertionError(f"expected exactly one successful claim, got {outcomes}")
        async with async_session() as db:
            auth = await db.get(ExecutionAuthorization, authorization_id)
            if auth is None or auth.consumed_count != 1:
                raise AssertionError("single-use authorization was not consumed exactly once")
        print(f"PASS concurrent claims={outcomes}; consumed_count=1")
    finally:
        if task_id is not None:
            async with async_session() as db, db.begin():
                await db.execute(delete(ToolTask).where(ToolTask.id == task_id))
                await db.execute(delete(ExecutionAuthorization).where(ExecutionAuthorization.id == authorization_id))
                await db.execute(delete(DecisionProposal).where(DecisionProposal.id == proposal_id))


if __name__ == "__main__":
    asyncio.run(main())
