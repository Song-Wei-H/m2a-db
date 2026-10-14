"""Opt-in PostgreSQL 16 integration for ToolResult/feedback transaction boundaries.

GADE_LEARNING_FEEDBACK_TEST_DATABASE_URL must point at a fresh, run-scoped local
test database. The test creates and drops only a UUID-named schema in that DB.
It does not run a Worker or manufacture a Worker receipt.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import replace
from pathlib import Path
from uuid import uuid4
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.action_contracts import ACTION_IDENTITIES, ACTION_TEMPLATES
from app.execution_governance import canonical_parameters, evaluate_and_authorize, parameter_hash
from app.execution_trace import context_evidence, execution_request, trace_tool_result
from app.models import (
    AuthorizationDecision,
    Base,
    DecisionScore,
    ExecutionAuthorization,
    LearningFeedback,
    OpenPort,
    Target,
    ToolRegistry,
    ToolResult,
    ToolTask,
    ValidationAction,
)
from app.tool_task_writer import create_tool_task_if_not_exists
from worker.task_poller import _claim_task, _load_task_context, _persist_result, _record_learning_feedback
from worker.tool_runner import ToolRunOutcome


@pytest.mark.asyncio
async def test_postgresql_tool_result_feedback_transactions_and_governance(monkeypatch):
    raw_url = os.environ.get("GADE_LEARNING_FEEDBACK_TEST_DATABASE_URL")
    if not raw_url:
        pytest.skip("Opt-in local PostgreSQL 16 database is not configured")

    url = make_url(raw_url)
    if url.host not in {"localhost", "127.0.0.1"}:
        pytest.fail("Integration test accepts only a local PostgreSQL host")
    if not url.database or not re.fullmatch(r"gade_[0-9a-f]{12}_fresh", url.database):
        pytest.fail("Integration test requires a run-scoped gade_<12-hex>_fresh database")

    admin_engine = create_async_engine(url)
    schema = "gade_lf_" + uuid4().hex
    test_engine = None
    output = {
        "database": url.database,
        "schema": schema,
        "postgres_server_version_num": None,
        "tool_result_id": None,
        "learning_feedback_rows": None,
        "feedback_failure_preserved_result": False,
        "feedback_retry_idempotent": False,
        "trace_relations_resolved": False,
        "single_use_grant_rejected": False,
        "unauthorized_worker_dispatch_blocked": False,
        "worker_receipt_created": False,
    }
    try:
        async with admin_engine.begin() as conn:
            version = await conn.scalar(text("SELECT current_setting('server_version_num')::integer"))
            assert int(version) // 10000 == 16, f"PostgreSQL 16 required, got server_version_num={version}"
            output["postgres_server_version_num"] = int(version)
            identity = (await conn.execute(text(
                "SELECT current_database(), current_user"
            ))).one()
            assert identity[0] == url.database
            output["database"] = identity[0]
            output["database_user"] = identity[1]
            await conn.execute(text(f'CREATE SCHEMA "{schema}"'))

        test_engine = create_async_engine(
            url,
            connect_args={"server_settings": {"search_path": schema}},
        )
        async with test_engine.begin() as conn:
            assert await conn.scalar(text("SELECT current_schema()")) == schema
            await conn.run_sync(Base.metadata.create_all)
            raw = await conn.get_raw_connection()
            await raw.driver_connection.execute(Path("initdb/033_execution_trace.sql").read_text(encoding="utf-8"))

        session_factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
        monkeypatch.setattr("worker.task_poller.async_session", session_factory)

        action = "http_security_headers.collect.v1"
        async with session_factory() as db, db.begin():
            target = Target(target="10.56.66.119", scope="10.56.66.119/32")
            db.add(target)
            await db.flush()
            port = OpenPort(target_id=target.id, port=18080, protocol="tcp", service="http")
            db.add(port)
            db.add(ToolRegistry(tool_name="http_security_headers", enabled=True))
            db.add(ValidationAction(
                action_id=action,
                tool_name="http_security_headers",
                phase="discovery",
                validation_tier=1,
                execution_identity=ACTION_IDENTITIES[action],
                template_version=ACTION_TEMPLATES[action],
                parameter_schema={},
                enabled=True,
            ))
            await db.flush()
            decision_score = DecisionScore(
                target_id=target.id,
                open_port_id=port.id,
                risk_score=0.0,
                next_action="continue",
                next_tool="http_security_headers",
                reason="isolated database integration fixture",
                input_snapshot={"target_id": target.id, "open_port_id": port.id},
            )
            db.add(decision_score)
            await db.flush()
            params = canonical_parameters(
                target=target.target,
                port=port.port,
                protocol=port.protocol,
                service=port.service,
                action_id=action,
            )
            governed = await evaluate_and_authorize(
                db,
                target=target,
                tool_name="http_security_headers",
                parameters=params,
                reason="isolated integration fixture",
                confidence=1.0,
                provider="test-fixture",
                authorization_source="gade-tier-policy",
                raw_proposal={"selected_action": action, "proposed_parameters": params},
                evidence_refs=context_evidence(target, port, decision_score),
                decision_score_id=decision_score.id,
            )
            assert governed.authorization is not None
            task, inserted = await create_tool_task_if_not_exists(
                db,
                target_id=target.id,
                open_port_id=port.id,
                tool_name="http_security_headers",
                status="pending",
                approval_status="not_required",
                decision_score_id=decision_score.id,
                investigation_id=governed.proposal.investigation_id,
                action_id=action,
                execution_authorization_id=governed.authorization.id,
            )
            assert inserted and task is not None

            assert await _claim_task(db, task.id)
            # Simulate an attempted replay after the single-use grant has been
            # consumed, while leaving the task otherwise claimable.
            task.status = "pending"
            await db.flush()
            assert not await _claim_task(db, task.id)
            output["single_use_grant_rejected"] = True
            task.status = "running"
            ctx = await _load_task_context(db, task)
            ctx = replace(
                ctx,
                execution_identity=governed.authorization.execution_identity,
                authorization_parameters=params,
                authorization_parameters_hash=governed.authorization.parameters_hash,
                authorization_id=governed.authorization.id,
            )
            request = execution_request(ctx)
            task.execution_request = request
            task.execution_request_hash = parameter_hash(request)
            task.execution_audit = {"stage": "prepared", "handler_invoked": None}

        outcome = ToolRunOutcome(
            command="builtin:http_security_headers",
            raw_output="test-only persisted result; no Worker was invoked",
            parsed_result={"status_code": 200},
            success=True,
            status="completed",
            error_message=None,
            execution_receipt=None,
        )
        # A: ToolResult is committed by itself, before feedback is attempted.
        async with session_factory() as db, db.begin():
            result_id = await _persist_result(db, ctx, outcome)
        output["tool_result_id"] = result_id
        async with session_factory() as db:
            assert await db.scalar(select(func.count(ToolResult.id)).where(ToolResult.id == result_id)) == 1

        # C: make the schema reject only the derived feedback write. The result
        # commit must survive, and the task must expose a retryable failure.
        async with test_engine.begin() as conn:
            await conn.execute(text(
                "ALTER TABLE learning_feedback RENAME COLUMN success TO success__integration_failure"
            ))
        try:
            assert not await _record_learning_feedback(result_id)
            async with session_factory() as db:
                assert await db.scalar(select(func.count(ToolResult.id)).where(ToolResult.id == result_id)) == 1
                task = await db.get(ToolTask, ctx.task_id)
                assert task.execution_audit["learning_feedback_status"] == "failed"
                assert task.execution_audit["learning_feedback_retryable"] is True
                assert task.execution_audit["learning_feedback_error"]
        finally:
            async with test_engine.begin() as conn:
                await conn.execute(text(
                    "ALTER TABLE learning_feedback RENAME COLUMN success__integration_failure TO success"
                ))
        output["feedback_failure_preserved_result"] = True

        # B/D: retry successfully, then repeat the retry. Row locking plus the
        # existing-row check must keep exactly one feedback row for this result.
        assert await _record_learning_feedback(result_id)
        assert await _record_learning_feedback(result_id)
        async with session_factory() as db:
            feedback_count = await db.scalar(select(func.count(LearningFeedback.id)).where(
                LearningFeedback.tool_result_id == result_id
            ))
            task = await db.get(ToolTask, ctx.task_id)
            assert feedback_count == 1
            assert task.execution_audit["learning_feedback_status"] == "complete"
        output["learning_feedback_rows"] = int(feedback_count)
        output["feedback_retry_idempotent"] = True

        async with session_factory() as db:
            trace = await trace_tool_result(db, result_id)
            assert trace["tool_task"]["id"] == ctx.task_id
            assert trace["execution_authorization"]["id"] == governed.authorization.id
            assert trace["authorization_decision"]["authorization_id"] == governed.authorization.id
            assert trace["decision"]["id"] == governed.proposal.id
            assert "worker_receipt_missing" in trace["issues"]
            assert not any(issue.endswith("_missing") for issue in trace["issues"] if issue != "worker_receipt_missing")
        output["trace_relations_resolved"] = True
        output["trace_status"] = trace["status"]
        output["trace_issues"] = trace["issues"]

        # G: a protected task without an AuthorizationGrant is never dispatched.
        async with session_factory() as db, db.begin():
            unauthorized = ToolTask(
                target_id=ctx.target_id,
                open_port_id=ctx.open_port_id,
                tool_name="http_security_headers",
                status="pending",
                approval_status="not_required",
                action_id=action,
            )
            db.add(unauthorized)
            await db.flush()
            unauthorized_id = unauthorized.id
        remote = AsyncMock()
        monkeypatch.setattr("worker.task_poller.run_remote_tool", remote)
        await __import__("worker.task_poller", fromlist=["execute_task"]).execute_task(unauthorized_id)
        remote.assert_not_awaited()
        output["unauthorized_worker_dispatch_blocked"] = True

        destination = os.environ.get("GADE_LEARNING_FEEDBACK_TEST_OUTPUT")
        if destination:
            Path(destination).write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    finally:
        if test_engine is not None:
            await test_engine.dispose()
        async with admin_engine.begin() as conn:
            await conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await admin_engine.dispose()
