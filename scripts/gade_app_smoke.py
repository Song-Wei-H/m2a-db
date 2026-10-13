"""Networkless, in-process application smoke for a verified clean scratch DB.

The host PowerShell wrapper proves the exact Docker container and 001-037 log
before supplying its password. This script additionally checks its TCP database
identity before any write. It never invokes a dispatcher, Worker, or tool.
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4


class SmokeFailure(Exception):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise SmokeFailure(reason)


async def run_smoke() -> int:
    stage = "environment"
    repo = Path(os.environ.get("M2A_APP_SMOKE_REPO", ""))
    password = os.environ.pop("M2A_APP_SMOKE_PASSWORD", "")
    container_id = os.environ.get("M2A_APP_SMOKE_CONTAINER_ID", "")
    db_host = os.environ.get("M2A_APP_SMOKE_HOST", "")
    db_port_text = os.environ.get("M2A_APP_SMOKE_PORT", "")
    db_name = os.environ.get("M2A_APP_SMOKE_DATABASE", "")
    db_user = os.environ.get("M2A_APP_SMOKE_USER", "")
    require(repo == Path(r"C:\Users\p2166\m2a-db") and repo.is_dir(), "repo_guard")
    require(bool(password), "password_missing")
    require(len(container_id) == 64 and all(c in "0123456789abcdef" for c in container_id), "container_id_guard")
    require(db_host == "127.0.0.1", "database_host_guard")
    require(db_port_text.isdigit() and 25436 <= int(db_port_text) <= 25999, "database_port_guard")
    require(
        db_name == db_user and len(db_name) == 23 and db_name.startswith("gade_") and db_name.endswith("_fresh"),
        "database_identity_guard",
    )
    db_port = int(db_port_text)
    require("app.config" not in sys.modules and "app.database" not in sys.modules, "application_preimported")
    # Build the only permissible URL before importing app.config or app.database.
    from sqlalchemy import func, select, text
    from sqlalchemy.engine import URL, make_url

    expected = URL.create(
        "postgresql+asyncpg",
        username=db_user,
        password=password,
        host=db_host,
        port=db_port,
        database=db_name,
    )
    os.environ["DATABASE_URL"] = expected.render_as_string(hide_password=False)
    sys.path.insert(0, str(repo))

    from httpx import ASGITransport, AsyncClient

    from app.config import settings
    from app.database import async_session, engine
    from app.execution_trace import trace_tool_result
    from app.main import app
    from app.models import (
        EvidenceConfidence,
        ExecutionAuthorization,
        LlmRecommendation,
        Target,
        ToolResult,
        ToolTask,
        VulnerabilityCandidate,
    )
    from app.vulnerability_queue import candidate_identity
    from app.attack_authorization import POLICY_VERSION

    configured = make_url(settings.database_url)
    require(
        configured.drivername == "postgresql+asyncpg"
        and configured.host == db_host
        and configured.port == db_port
        and configured.database == db_name
        and configured.username == db_user
        and configured.password == password,
        "application_url_guard",
    )
    password = ""

    marker = "gade-app-smoke-" + uuid4().hex
    target_name = marker + ".invalid"
    target_id: int | None = None
    candidate_id: int | None = None
    result_id: int | None = None
    evidence_confidence_id: int | None = None
    llm_recommendation_id: int | None = None
    failure: tuple[str, str] | None = None
    cleanup_failure: str | None = None

    try:
        stage = "database_identity"
        async with engine.connect() as conn:
            identity = (
                await conn.execute(
                    text("SELECT current_database(), current_user, inet_server_port()")
                )
            ).one()
            require(tuple(identity) == (db_name, db_user, 5432), "database_identity_mismatch")
            schema = (
                await conn.execute(
                    text(
                        "SELECT to_regclass('public.vulnerability_candidates') IS NOT NULL, "
                        "EXISTS (SELECT 1 FROM information_schema.columns "
                        "WHERE table_schema='public' AND table_name='vulnerability_candidates' "
                        "AND column_name='validation_coverage'), "
                        "EXISTS (SELECT 1 FROM pg_constraint "
                        "WHERE conrelid='public.targets'::regclass "
                        "AND conname='targets_authorization_depth_range')"
                    )
                )
            ).one()
            require(tuple(schema) == (True, True, True), "required_schema_missing")
            existing = (
                await conn.execute(
                    text(
                        "SELECT (SELECT count(*) FROM targets), "
                        "(SELECT count(*) FROM tool_tasks), "
                        "(SELECT count(*) FROM tool_results), "
                        "(SELECT count(*) FROM vulnerability_candidates)"
                    )
                )
            ).one()
            require(tuple(existing) == (0, 0, 0, 0), "scratch_application_tables_not_empty")
        print(f"DATABASE_IDENTITY=PASS database={db_name} user={db_user} tcp_port=5432")
        print("SCRATCH_APPLICATION_STATE=PASS targets=0 tasks=0 results=0 candidates=0")

        stage = "target_create_read"
        async with async_session() as session:
            target = Target(
                target=target_name,
                target_type="domain",
                scope="internal",
                status="stopped",
                authorization_depth=1,
                authorization_policy_version=POLICY_VERSION,
                authorization_effective_from=datetime.now(UTC).replace(tzinfo=None),
                authorization_configured_by="scratch-app-smoke",
            )
            session.add(target)
            await session.commit()
            target_id = target.id
        require(target_id is not None, "target_id_missing")
        async with async_session() as session:
            stored = await session.get(Target, target_id)
            require(stored is not None and stored.target == target_name and stored.status == "stopped", "target_read_mismatch")
            tasks = await session.scalar(select(func.count(ToolTask.id)).where(ToolTask.target_id == target_id))
            require(tasks == 0, "unexpected_tool_task")
        print("TARGET_ORM_CREATE_READ=PASS; tool_tasks=0; status=stopped")

        stage = "http_health_authorization"
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://app-smoke.invalid") as client:
            health = await client.get("/health")
            require(health.status_code == 200 and health.json().get("status") == "ok", "health_response")
            original = await client.get(f"/targets/{target_id}/authorization")
            require(original.status_code == 200 and original.json().get("authorization_depth") == 1, "authorization_initial")
            changed = await client.put(f"/targets/{target_id}/authorization", json={"authorization_depth": 2})
            require(changed.status_code == 200 and changed.json().get("authorization_depth") == 2, "authorization_update")
            profile = await client.get(f"/targets/{target_id}/authorization")
            require(profile.status_code == 200 and profile.json().get("authorization_depth") == 2, "authorization_readback")
            require(profile.json().get("configured_by") == "operator-ui", "authorization_audit_field")
        print("HTTP_HEALTH=PASS")
        print("HTTP_AUTHORIZATION_GET_PUT_GET=PASS depth=1_to_2")

        stage = "candidate_create_read"
        fixture_cve = "CVE-1900-0001"
        async with async_session() as session:
            candidate = VulnerabilityCandidate(
                target_id=target_id,
                cve=fixture_cve,
                candidate_key=candidate_identity(target_id, fixture_cve, None, None, []),
                evidence_refs=[],
                required_action=None,
                validation_result=None,
            )
            session.add(candidate)
            await session.commit()
            candidate_id = candidate.id
        require(candidate_id is not None, "candidate_id_missing")
        async with async_session() as session:
            stored = await session.get(VulnerabilityCandidate, candidate_id)
            require(
                stored is not None
                and stored.target_id == target_id
                and stored.status == "DISCOVERED"
                and stored.validation_coverage == "NOT_EVALUATED"
                and stored.validation_result is None
                and stored.authorization_decision_id is None
                and stored.execution_authorization_id is None
                and stored.tool_task_id is None,
                "candidate_readback_or_default_mismatch",
            )
        print("CANDIDATE_ORM_CREATE_READ=PASS status=DISCOVERED coverage=NOT_EVALUATED")

        stage = "migration037_jsonb_orm_roundtrip"
        supporting = {"fixture": "migration037", "items": ["source-a", "source-b"]}
        contradictory = {"checked": True, "count": 0}
        raw_response = {"fixture": "migration037", "recommendation": "observe"}
        async with async_session() as session:
            confidence = EvidenceConfidence(
                target_id=target_id,
                tool_name="fixture_only",
                evidence_type="controlled_smoke",
                confidence_score=0.75,
                confidence_reason="isolated schema smoke fixture",
                supporting_evidence=supporting,
                contradictory_evidence=contradictory,
            )
            session.add(confidence)
            await session.flush()
            recommendation = LlmRecommendation(
                target_id=target_id,
                evidence_confidence_id=confidence.id,
                recommended_action="observe",
                recommended_tool="fixture_only",
                confidence=0.75,
                reasoning="isolated schema smoke fixture",
                raw_response=raw_response,
                validator_status="FIXTURE_ONLY",
                validator_reason="No production action requested",
            )
            session.add(recommendation)
            await session.commit()
            evidence_confidence_id = confidence.id
            llm_recommendation_id = recommendation.id
        require(evidence_confidence_id is not None and llm_recommendation_id is not None, "migration037_ids_missing")
        async with async_session() as session:
            confidence = await session.get(EvidenceConfidence, evidence_confidence_id)
            recommendation = await session.get(LlmRecommendation, llm_recommendation_id)
            require(
                confidence is not None
                and confidence.target_id == target_id
                and confidence.supporting_evidence == supporting
                and confidence.contradictory_evidence == contradictory
                and confidence.created_at is not None,
                "evidence_confidence_jsonb_readback",
            )
            require(
                recommendation is not None
                and recommendation.target_id == target_id
                and recommendation.evidence_confidence_id == evidence_confidence_id
                and recommendation.raw_response == raw_response
                and recommendation.approved is False
                and recommendation.created_at is not None,
                "llm_recommendation_jsonb_readback",
            )
        print("MIGRATION_037_SQLALCHEMY_INSERT_SELECT=PASS tables=2 jsonb=roundtrip defaults=server")

        stage = "historical_trace_persistence"
        async with async_session() as session:
            historical = ToolResult(target_id=target_id, tool_name="fixture_no_execution", success=False)
            session.add(historical)
            await session.commit()
            result_id = historical.id
        require(result_id is not None, "tool_result_id_missing")
        async with async_session() as session:
            trace = await trace_tool_result(session, result_id)
            require(
                trace["status"] == "PARTIAL"
                and "tool_task_missing" in trace["issues"]
                and trace["tool_result"]["execution_receipt"] is None,
                "historical_trace_boundary_mismatch",
            )
        print("HISTORICAL_TRACE=PASS status=PARTIAL receipt=NULL; no Worker executed")

        stage = "http_report"
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://app-smoke.invalid") as client:
            report_response = await client.get(f"/targets/{target_id}/report")
            require(report_response.status_code == 200, "report_http_status")
            report = report_response.json()
            queue = report.get("vulnerability_queue", [])
            coverage = report.get("vulnerability_coverage", {})
            require(report.get("target_summary", {}).get("target_id") == target_id, "report_target_identity")
            require(
                len(queue) == 1
                and queue[0].get("candidate_id") == candidate_id
                and queue[0].get("status") == "DISCOVERED"
                and queue[0].get("validation_coverage") == "NOT_EVALUATED",
                "report_queue_mismatch",
            )
            require(
                coverage.get("verified") == 0
                and coverage.get("not_verified") == 0
                and coverage.get("technically_covered_candidates") == 0
                and coverage.get("omission_count") == 1,
                "report_false_validation_claim",
            )
            status = await client.get(f"/targets/{target_id}/run-status")
            require(status.status_code == 200 and status.json().get("pending_task_count") == 0, "run_status_tasks")
        async with async_session() as session:
            tasks = await session.scalar(select(func.count(ToolTask.id)).where(ToolTask.target_id == target_id))
            grants = await session.scalar(
                select(func.count(ExecutionAuthorization.id)).where(ExecutionAuthorization.target_id == target_id)
            )
            require(tasks == 0 and grants == 0, "unexpected_execution_authority")
        print("HTTP_REPORT=PASS queue=DISCOVERED/NOT_EVALUATED; verified=0; not_verified=0")
        print("NO_EXECUTION_AUTHORITY=PASS tasks=0 grants=0")

    except Exception as exc:
        detail = exc.args[0] if isinstance(exc, SmokeFailure) and exc.args else type(exc).__name__
        failure = (stage, str(detail))
    finally:
        # Delete only rows created by this run, in dependency order. Any failed
        # cleanup leaves the scratch DB intact for investigation and fails smoke.
        if target_id is not None:
            try:
                async with async_session() as session:
                    stored = await session.get(Target, target_id)
                    require(stored is not None and stored.target == target_name, "cleanup_target_guard")
                    if result_id is not None:
                        row = await session.get(ToolResult, result_id)
                        require(row is not None and row.target_id == target_id and row.tool_name == "fixture_no_execution", "cleanup_result_guard")
                        await session.delete(row)
                    if llm_recommendation_id is not None:
                        row = await session.get(LlmRecommendation, llm_recommendation_id)
                        require(row is not None and row.target_id == target_id, "cleanup_llm_recommendation_guard")
                        await session.delete(row)
                    if evidence_confidence_id is not None:
                        row = await session.get(EvidenceConfidence, evidence_confidence_id)
                        require(row is not None and row.target_id == target_id, "cleanup_evidence_confidence_guard")
                        await session.delete(row)
                    if candidate_id is not None:
                        row = await session.get(VulnerabilityCandidate, candidate_id)
                        require(row is not None and row.target_id == target_id, "cleanup_candidate_guard")
                        await session.delete(row)
                    await session.flush()
                    await session.delete(stored)
                    await session.commit()
                async with async_session() as session:
                    remaining = await session.scalar(select(func.count(Target.id)).where(Target.id == target_id))
                    require(remaining == 0, "cleanup_target_remains")
                print("CLEANUP=PASS")
            except Exception as exc:
                cleanup_failure = exc.args[0] if isinstance(exc, SmokeFailure) and exc.args else type(exc).__name__
                print(f"CLEANUP=FAIL detail={cleanup_failure}")
        else:
            print("CLEANUP=PASS no_rows_created")
        await engine.dispose()

    if failure is not None or cleanup_failure is not None:
        if failure is not None:
            print(f"APP_SMOKE=FAIL stage={failure[0]} detail={failure[1]}")
        else:
            print("APP_SMOKE=FAIL stage=cleanup")
        return 1
    print("APP_SMOKE=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(run_smoke()))
    except Exception as exc:
        # The setup path is before app imports and before any DB mutation.
        detail = exc.args[0] if isinstance(exc, SmokeFailure) and exc.args else type(exc).__name__
        print(f"APP_SMOKE=FAIL stage=environment detail={detail}")
        raise SystemExit(1)
