"""Networkless Worker tests and opt-in PostgreSQL transactional integration.

GADE_TRACE_TEST_ENV_FILE may name a local dotenv containing DATABASE_URL.
Only a new transaction-local schema is touched; rollback preserves all real rows.
"""
import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from app.action_contracts import ACTION_IDENTITIES, ACTION_TEMPLATES
from app.execution_governance import evaluate_and_authorize, canonical_parameters, parameter_hash
from app.execution_trace import (context_evidence, execution_request, trace_tool_result,
                                 proposal_input, result_output, evaluation_matches_grant,
                                 grant_contract)
from app.models import (Base, Target, OpenPort, DecisionScore, DecisionProposal,
                        AuthorizationDecision, ExecutionAuthorization, ToolResult, ToolTask, ValidationAction)
from app.tool_task_writer import create_tool_task_if_not_exists
from kali_worker.app import ExecuteRequest, execute
from worker.task_poller import _claim_task, _load_task_context, _persist_result
from worker.tool_runner import ToolRunOutcome


def test_evaluation_snapshot_allows_policy_metadata_but_matches_entire_grant_contract():
    grant = SimpleNamespace(
        id=7, proposal_id=8, target_id=9, investigation_id="inv-1", action_id="http.headers.v1",
        canonical_parameters={"target": "trace.example", "port": 80}, parameters_hash="abc",
        execution_identity={"binary": "safe"}, template_version="v1", validation_tier=1,
        scope={"target": "trace.example"}, execution_limit=1,
        expires_at=None, authorization_source="gade-tier-policy",
    )
    expected = grant_contract(grant)
    evaluation = SimpleNamespace(contract_snapshot={
        **expected, "policy_version": "m2a-attack-depth-v1", "depth_check": "PASS",
        "evidence_check": "PASS", "approval_check": "PASS", "reason_code": None,
    })
    assert evaluation_matches_grant(evaluation, grant)

    evaluation.contract_snapshot["action_id"] = "different.action"
    assert not evaluation_matches_grant(evaluation, grant)

    evaluation.contract_snapshot = dict(expected)
    del evaluation.contract_snapshot["execution_identity"]
    assert not evaluation_matches_grant(evaluation, grant)

    evaluation.contract_snapshot = None
    assert not evaluation_matches_grant(evaluation, grant)


def test_actual_argv_drift_never_calls_subprocess():
    action = "httpx.web_probe.v1"
    params = canonical_parameters(target="trace.example", port=80, protocol="tcp", service="http", action_id=action)
    req = ExecuteRequest(tool="httpx_basic", target="trace.example", port=80, protocol="tcp", service="http",
        action_id=action, execution_identity=ACTION_IDENTITIES[action], authorization_parameters=params,
        authorization_parameters_hash=parameter_hash(params), task_id=10, authorization_id=20)
    from kali_worker.app import run_command
    with patch("kali_worker.app.resolve_target", return_value=["192.0.2.10"]), \
         patch("kali_worker.app.run_httpx", side_effect=lambda *args: run_command(["httpx", "-u", "http://other.example/"])), \
         patch("kali_worker.app.subprocess.run") as process:
        result = execute(req)
    process.assert_not_called()
    assert result["status"] == "rejected"
    assert result["execution_receipt"]["executed_parameters"] != params
    assert result["execution_receipt"]["subprocess_started"] is False


@pytest.mark.asyncio
async def test_postgresql_trace_chain():
    config_path = os.environ.get("GADE_TRACE_TEST_ENV_FILE")
    if not config_path:
        pytest.skip("Opt-in PostgreSQL connection required; no production schema is used")
    from dotenv import dotenv_values
    url = make_url(dotenv_values(config_path)["DATABASE_URL"])
    if url.host not in {"localhost", "127.0.0.1"}:
        pytest.fail("Trace integration only accepts a local PostgreSQL host")
    engine = create_async_engine(url)
    schema = "gade_trace_test_" + uuid4().hex
    try:
        async with engine.connect() as conn:
            tx = await conn.begin()
            try:
                await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
                await conn.execute(text(f'SET LOCAL search_path TO "{schema}"'))
                await conn.run_sync(Base.metadata.create_all)
                # Reproduce the deployed legacy shape: the column exists but its
                # FK was skipped by an earlier ADD COLUMN IF NOT EXISTS migration.
                await conn.execute(text(
                    "ALTER TABLE tool_results DROP CONSTRAINT IF EXISTS "
                    "tool_results_tool_task_id_fkey"
                ))
                raw = await conn.get_raw_connection()
                migration = Path("initdb/033_execution_trace.sql").read_text(encoding="utf-8")
                await raw.driver_connection.execute(migration)
                await raw.driver_connection.execute(migration)
                fk = (await conn.execute(text("""
                    SELECT convalidated FROM pg_constraint c
                    WHERE c.conrelid='tool_results'::regclass AND c.contype='f'
                      AND c.conkey=ARRAY[(SELECT attnum FROM pg_attribute
                                         WHERE attrelid='tool_results'::regclass
                                           AND attname='tool_task_id')]::smallint[]
                """))).scalar_one()
                assert fk is False
                async with AsyncSession(bind=conn, expire_on_commit=False, join_transaction_mode="create_savepoint") as db:
                    target = Target(target="trace.example", scope="internal")
                    db.add(target)
                    await db.flush()
                    port = OpenPort(target_id=target.id, port=80, protocol="tcp", service="http")
                    db.add(port)
                    await db.flush()
                    decision = DecisionScore(target_id=target.id, open_port_id=port.id, risk_score=0.0,
                        next_action="continue", next_tool="http_security_headers", reason="Fixture HTTP evidence",
                        input_snapshot={"open_port_id": port.id, "target": target.target, "port": 80})
                    db.add(decision)
                    action = "http_security_headers.collect.v1"
                    db.add(ValidationAction(action_id=action, tool_name="http_security_headers", phase="discovery",
                        validation_tier=1, execution_identity=ACTION_IDENTITIES[action],
                        template_version=ACTION_TEMPLATES[action], parameter_schema={}, enabled=True))
                    await db.flush()
                    params = canonical_parameters(target=target.target, port=80, protocol="tcp", service="http", action_id=action)
                    # The proposal asks for a different port. Policy materialization
                    # uses evidence-derived parameters, preserving both for comparison.
                    original = {"selected_action": action, "proposed_parameters": {**params, "port": 8080}}
                    governed = await evaluate_and_authorize(db, target=target, tool_name="http_security_headers",
                        parameters=params, reason="authority reconstruction", confidence=1.0, provider="fixture",
                        authorization_source="gade-tier-policy", raw_proposal=original,
                        evidence_refs=context_evidence(target, port, decision), decision_score_id=decision.id)
                    original["proposed_parameters"]["port"] = 1234
                    assert governed.proposal.raw_proposal["proposed_parameters"]["port"] == 8080
                    assert governed.evaluation.outcome == "ALLOW"
                    task, inserted = await create_tool_task_if_not_exists(db, target_id=target.id, open_port_id=port.id,
                        tool_name="http_security_headers", status="pending", approval_status="not_required",
                        decision_score_id=decision.id, investigation_id=governed.proposal.investigation_id,
                        action_id=action, execution_authorization_id=governed.authorization.id)
                    assert inserted
                    assert await _claim_task(db, task.id)
                    assert not await _claim_task(db, task.id)
                    ctx = await _load_task_context(db, task)
                    ctx = replace(ctx, execution_identity=governed.authorization.execution_identity,
                        authorization_parameters=params, authorization_parameters_hash=parameter_hash(params),
                        authorization_id=governed.authorization.id)
                    request = execution_request(ctx)
                    task.execution_request = request
                    task.execution_request_hash = parameter_hash(request)
                    await db.flush()
                    with patch("kali_worker.app.resolve_target", return_value=["192.0.2.10"]), \
                         patch("kali_worker.app.run_http_security_headers", return_value={
                             "status": "completed", "command": "builtin:http_security_headers", "raw_output": "fixture",
                             "parsed_result": {"status_code": 200}}):
                        received = execute(ExecuteRequest(**request))
                    outcome = ToolRunOutcome(command=received["command"], raw_output=received["raw_output"],
                        parsed_result=received["parsed_result"], success=True, status="completed",
                        execution_receipt=received["execution_receipt"])
                    with patch("worker.learning_feedback.create_learning_feedback", new=AsyncMock()):
                        result_id = await _persist_result(db, ctx, outcome)
                    await db.commit()
                    db.expire_all()
                    trace = await trace_tool_result(db, result_id)
                    assert trace["status"] == "COMPLETE", trace["issues"]
                    assert trace["proposal_to_authority_drift"] is True
                    # DENY must survive a commit and have no executable grant/task/result.
                    target = await db.get(Target, trace["tool_task"]["target_id"])
                    denied = await evaluate_and_authorize(db, target=target, tool_name="unregistered",
                        parameters={}, reason="unknown action", confidence=None, provider="fixture",
                        authorization_source="gade-tier-policy", raw_proposal={"selected_action": "unregistered"},
                        evidence_refs=context_evidence(target))
                    deny_id = denied.evaluation.id
                    deny_proposal_id = denied.proposal.id
                    assert denied.authorization is None
                    await db.commit()
                    db.expire_all()
                    deny_row = await db.get(AuthorizationDecision, deny_id)
                    assert deny_row.outcome == "DENY" and deny_row.authorization_id is None
                    assert (await db.execute(select(ExecutionAuthorization).where(
                        ExecutionAuthorization.proposal_id == deny_proposal_id))).scalars().all() == []
                    assert (await db.execute(select(ToolTask))).scalars().all().__len__() == 1
                    assert (await db.execute(select(ToolResult))).scalars().all().__len__() == 1
                    # Legacy null references are visible as partial, never backfilled.
                    historical = ToolResult(
                        target_id=trace["tool_task"]["target_id"],
                        tool_name="historical",
                        success=False,
                    )
                    db.add(historical)
                    await db.flush()
                    partial = await trace_tool_result(db, historical.id)
                    assert partial["status"] == "PARTIAL" and "tool_task_missing" in partial["issues"]
                    # FK must reject NEW orphan results, retaining historical nulls.
                    with pytest.raises(Exception, match="foreign key|ForeignKey"):
                        async with db.begin_nested():
                            db.add(ToolResult(tool_task_id=999999, success=False))
                            await db.flush()
                    # Database protects snapshots even when bypassing ORM/service.
                    for sql in [
                        f"UPDATE decision_proposals SET raw_proposal='{{}}' WHERE id={trace['decision']['id']}",
                        f"UPDATE execution_authorizations SET canonical_parameters='{{}}' WHERE id={trace['execution_authorization']['id']}",
                        f"UPDATE tool_results SET success=false WHERE id={result_id}",
                        f"UPDATE authorization_decisions SET outcome='DENY' WHERE id={trace['authorization_decision']['id']}",
                    ]:
                        with pytest.raises(Exception, match="immutable|append-only"):
                            async with db.begin_nested():
                                await db.execute(text(sql))
                    payload = {"schema": schema, "migration_applied_twice": True,
                               "allow_trace": trace, "deny": {"evaluation_id": deny_id,
                               "proposal_id": deny_proposal_id, "outcome": "DENY", "authorization_id": None,
                               "tasks": 0, "results": 0}, "legacy": partial,
                               "scope": "PostgreSQL ORM + networkless Worker handler fixture; transaction rolled back"}
                    destination = os.environ.get("GADE_TRACE_OUTPUT")
                    if destination:
                        Path(destination).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            finally:
                await tx.rollback()
    finally:
        await engine.dispose()
