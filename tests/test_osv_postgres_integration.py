"""Opt-in PostgreSQL integration test; requires a disposable loopback OSV test DB.

Set DATABASE_URL and M2A_OSV_PG_TEST_URL to the same isolated URL, with a
database name beginning `osv_test_`. This test never calls live OSV or a model.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import uuid

import httpx
import pytest
from sqlalchemy import select, text
from sqlalchemy.engine import make_url

from app.config import settings
from app.database import async_session, engine
from app.models import DecisionScore, LlmRecommendation, NormalizedResult, OsvNormalizedEvidence, OsvPackageQueryCache
from worker.analysis_pipeline import _persist_normalized_evidence
from worker.llm_decision import build_payload
from worker.osv_enrichment import (
    OSVClient,
    build_enrichment_context,
    enrich_normalized_result,
    get_osv_context_for_normalized_result,
)
from worker.package_identity import extract_package_identities
from worker.risk_engine_v3 import _calculate_evidence_adjustment_v3, calculate_risk_v3


PG_TEST_URL = os.environ.get("M2A_OSV_PG_TEST_URL")
pytestmark = pytest.mark.skipif(not PG_TEST_URL, reason="requires explicit isolated PostgreSQL OSV test URL")


def _assert_isolated_test_database() -> None:
    assert PG_TEST_URL
    url = make_url(PG_TEST_URL)
    assert url.drivername == "postgresql+asyncpg", "test must use the application's async PostgreSQL driver"
    assert url.host in {"127.0.0.1", "localhost", "::1"}, "test DB must be loopback only"
    assert (url.database or "").startswith("osv_test_"), "test database name must start with osv_test_"
    assert url.database != "m2a_pentest", "formal database is forbidden"
    assert url.port != 15432, "formal PostgreSQL port is forbidden"
    assert make_url(settings.database_url) == url, "application engine is not bound to the explicitly approved test URL"


async def _new_target_id() -> int:
    async with async_session() as session, session.begin():
        return int(await session.scalar(text("INSERT INTO targets DEFAULT VALUES RETURNING id")))


async def _persist(target_id: int, payload: dict) -> int:
    ids = await _persist_normalized_evidence(
        target_id=target_id,
        open_port_id=None,
        tool_name="osv_pg16_integration",
        tool_result_id=None,
        evidence_list=[payload],
    )
    assert len(ids) == 1
    return ids[0]


def _client(handler, *, max_retries: int = 0) -> OSVClient:
    async def no_sleep(_seconds: float) -> None:
        await asyncio.sleep(0)

    return OSVClient(
        base_url="https://osv.mock.invalid",
        timeout_seconds=0.5,
        max_retries=max_retries,
        rate_limit_per_second=0,
        transport=httpx.MockTransport(handler),
        sleep=no_sleep,
    )


async def _read_cache(identity: dict) -> OsvPackageQueryCache:
    identities, status = extract_package_identities({"package_identity": identity})
    assert status == "ready" and len(identities) == 1
    async with async_session() as session:
        result = await session.execute(
            select(OsvPackageQueryCache).where(OsvPackageQueryCache.cache_key == identities[0].cache_key)
        )
        row = result.scalar_one()
        return row


@pytest.mark.asyncio
async def test_osv_postgres_persistence_cache_risk_and_decision_context():
    _assert_isolated_test_database()
    async with engine.connect() as connection:
        version_num = int(await connection.scalar(text("SHOW server_version_num")))
        database_name = await connection.scalar(text("SELECT current_database()"))
        tables = await connection.execute(text("""
            SELECT to_regclass('public.normalized_results') IS NOT NULL,
                   to_regclass('public.osv_package_query_cache') IS NOT NULL,
                   to_regclass('public.osv_normalized_evidence') IS NOT NULL,
                   to_regclass('public.vulnerability_candidates') IS NOT NULL
        """))
        has_normalized, has_cache, has_evidence, has_vulnerability_candidates = tables.one()
    assert 160000 <= version_num < 170000
    assert database_name.startswith("osv_test_")
    assert has_normalized and has_cache and has_evidence
    assert has_vulnerability_candidates, "primary E2E DB must include the separately tested 035 schema"

    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: DecisionScore.__table__.create(sync, checkfirst=True))
        await connection.run_sync(lambda sync: LlmRecommendation.__table__.create(sync, checkfirst=True))

    target_id = await _new_target_id()
    unique = uuid.uuid4().hex[:10]
    identity = {"ecosystem": "npm", "name": f"osv-pg-{unique}", "version": "1.2.3"}
    normalized_id = await _persist(target_id, {"package_identity": identity, "success": True})
    visible_before_query: list[bool] = []
    requests: list[bytes] = []
    advisory_body = json.dumps({
        "vulns": [{"id": "GHSA-test-1234", "aliases": ["CVE-2026-12345"], "summary": "synthetic advisory"}]
    }).encode()

    async def advisory_handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.content)
        async with async_session() as session:
            visible_before_query.append(await session.get(NormalizedResult, normalized_id) is not None)
        await asyncio.sleep(0.03)
        return httpx.Response(200, content=advisory_body, headers={"Content-Type": "application/json"})

    client = _client(advisory_handler)
    try:
        await asyncio.gather(
            enrich_normalized_result(normalized_id, enabled=True, client=client),
            enrich_normalized_result(normalized_id, enabled=True, client=client),
        )
        osv_context = await get_osv_context_for_normalized_result(normalized_id)
        context = build_enrichment_context(osv_context=osv_context)
        assert len(requests) == 1, "concurrent initial lookup must be cache-claimed once"
        assert visible_before_query == [True], "NormalizedResult must commit before OSV I/O"
        assert context["osv"]["status"] == "complete"
        assert context["osv"]["cve_aliases"] == ["CVE-2026-12345"]
        cache = await _read_cache(identity)
        original_response_hash = hashlib.sha256(advisory_body).hexdigest()
        assert cache.status == "complete" and cache.response_sha256 == original_response_hash
        async with async_session() as session:
            evidence_rows = list((await session.execute(
                select(OsvNormalizedEvidence).where(OsvNormalizedEvidence.normalized_result_id == normalized_id)
            )).scalars().all())
        assert len(evidence_rows) == 1
        assert evidence_rows[0].cache_id == cache.id
        assert evidence_rows[0].evidence_ref == f"normalized_results:{normalized_id}"
        assert evidence_rows[0].status == "complete"

        # A second NormalizedResult with the same explicit package identity reuses
        # the cache and creates only its own evidence-to-cache association.
        normalized_id_2 = await _persist(target_id, {"package_identity": identity, "success": True, "case": unique})
        second_context = await enrich_normalized_result(normalized_id_2, enabled=True, client=client)
        assert len(requests) == 1
        assert second_context["status"] == "complete"

        risk_input = {"success": True, "enrichment_context": context}
        _, risk_components, _ = _calculate_evidence_adjustment_v3(
            tool_name="osv_pg16_integration", parsed_output=risk_input, base_confidence=0.9
        )
        assert risk_components["osv_advisory_candidate"]["candidate_count"] == 1, context["osv"].get("package_states")
        assert risk_components["osv_advisory_candidate"]["confirmed_vulnerability"] is False
        risk = calculate_risk_v3(
            target_id=target_id, open_port_id=None, service="http", port=8080,
            cvss=None, epss=None, kev=False, tool_name="osv_pg16_integration",
            parsed_output=risk_input, raw_output="", base_confidence=0.9,
        )
        async with async_session() as session, session.begin():
            score = DecisionScore(
                target_id=target_id,
                risk_score=risk.risk_score,
                next_action=risk.next_action,
                next_tool=risk.next_tool,
                reasoning=risk.reasoning,
                input_snapshot={"parsed_output": risk_input, "enrichment_context": context},
            )
            session.add(score)
            await session.flush()
            score_id = score.id
        async with async_session() as session:
            decision = await session.get(DecisionScore, score_id)
        payload = await build_payload(decision)
        assert payload["enrichment_context"]["osv"]["evidence_refs"][0]["ref"] == f"normalized_results:{normalized_id}"
        assert payload["enrichment_context"]["osv"]["trust"] == "untrusted_external_advisory"

        # Empty OSV responses are recorded as no_match, never as proof that the
        # target has no vulnerability. The risk model receives no candidate.
        no_match_identity = {"ecosystem": "npm", "name": f"osv-empty-{unique}", "version": "9.9.9"}
        no_match_id = await _persist(target_id, {"package_identity": no_match_identity})
        async def empty_handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={})
        empty_client = _client(empty_handler)
        try:
            no_match_context = await enrich_normalized_result(no_match_id, enabled=True, client=empty_client)
        finally:
            await empty_client.aclose()
        assert no_match_context["status"] == "no_match"
        assert no_match_context["result_semantics"] == "no_match_is_not_proof_of_no_vulnerability"
        _, no_match_components, _ = _calculate_evidence_adjustment_v3(
            tool_name="osv_pg16_integration",
            parsed_output={"enrichment_context": {"osv": no_match_context}}, base_confidence=0.9,
        )
        assert no_match_components["osv_advisory_candidate"]["candidate_count"] == 0
        assert no_match_components["osv_advisory_candidate"]["confirmed_vulnerability"] is False

        # Refresh failure must expose a stale/error state without overwriting the
        # last successful response, hash, timestamp, or advisory summary.
        async with async_session() as session, session.begin():
            await session.execute(
                text("UPDATE osv_package_query_cache SET expires_at = now() - interval '1 second' WHERE id = :id"),
                {"id": cache.id},
            )
        refresh_calls = 0
        async def refresh_timeout_handler(request: httpx.Request) -> httpx.Response:
            nonlocal refresh_calls
            refresh_calls += 1
            raise httpx.ReadTimeout("mock refresh timeout", request=request)
        refresh_client = _client(refresh_timeout_handler, max_retries=0)
        try:
            stale_context = await enrich_normalized_result(normalized_id, enabled=True, client=refresh_client)
        finally:
            await refresh_client.aclose()
        preserved_cache = await _read_cache(identity)
        assert refresh_calls == 1
        assert preserved_cache.status == "complete"
        assert preserved_cache.response_sha256 == original_response_hash
        assert preserved_cache.response_summary["vulnerabilities"][0]["id"] == "GHSA-test-1234"
        assert stale_context["package_states"][0]["status"] == "stale"
        assert stale_context["package_states"][0]["error_code"] == "timeout"

        # Product-only/version-unverified input is unsupported and must not query.
        calls_before_unsupported = len(requests)
        unknown_version_id = await _persist(target_id, {"product": "demo-product", "version_status": "Version Unverified"})
        unknown_context = await enrich_normalized_result(unknown_version_id, enabled=True, client=client)
        assert unknown_context["status"] == "unsupported"
        assert len(requests) == calls_before_unsupported

        # A first-time transient outage is a persisted failure, and the already
        # committed NormalizedResult remains available for later processing.
        failed_identity = {"ecosystem": "npm", "name": f"osv-timeout-{unique}", "version": "1.0.0"}
        failed_id = await _persist(target_id, {"package_identity": failed_identity})
        timeout_calls = 0
        async def timeout_handler(request: httpx.Request) -> httpx.Response:
            nonlocal timeout_calls
            timeout_calls += 1
            raise httpx.ReadTimeout("mock timeout", request=request)
        timeout_client = _client(timeout_handler, max_retries=1)
        try:
            failed_context = await enrich_normalized_result(failed_id, enabled=True, client=timeout_client)
        finally:
            await timeout_client.aclose()
        assert timeout_calls == 2
        assert failed_context["status"] == "failed"
        failed_cache = await _read_cache(failed_identity)
        assert failed_cache.status == "failed" and failed_cache.error_code == "timeout"
        async with async_session() as session:
            assert await session.get(NormalizedResult, failed_id) is not None

        # Disabled default preserves the legacy path and performs no query/write.
        assert settings.osv_enrichment_enabled is False
        disabled_id = await _persist(target_id, {"package_identity": {"ecosystem": "npm", "name": f"disabled-{unique}", "version": "1.0"}})
        calls_before_disabled = len(requests)
        disabled_context = await enrich_normalized_result(disabled_id, client=client)
        assert disabled_context["osv"]["status"] == "disabled"
        assert len(requests) == calls_before_disabled
        async with async_session() as session:
            rows = list((await session.execute(
                select(OsvNormalizedEvidence).where(OsvNormalizedEvidence.normalized_result_id == disabled_id)
            )).scalars().all())
        assert rows == []
    finally:
        await client.aclose()
        await engine.dispose()
