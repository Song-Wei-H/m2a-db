import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import httpx
import pytest

from app.models import NormalizedResult, OsvNormalizedEvidence, OsvPackageQueryCache
from worker.osv_enrichment import OSVClient, OSVLookup, build_enrichment_context, enrich_normalized_result
from worker.package_identity import extract_package_identities


class FakeResult:
    def __init__(self, rows):
        self.rows = list(rows)

    def scalar_one_or_none(self):
        return self.rows[0] if self.rows else None

    def scalars(self):
        return self

    def all(self):
        return self.rows


class FakeSession:
    def __init__(self, normalized):
        self.normalized = normalized
        self.caches = {}
        self.evidence = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    def begin(self):
        return self

    async def get(self, model, identity):
        if model is NormalizedResult:
            return self.normalized if self.normalized.id == identity else None
        if model is OsvPackageQueryCache:
            return next((row for row in self.caches.values() if row.id == identity), None)
        return None

    async def execute(self, statement, params=None):
        if "pg_advisory_xact_lock" in str(statement):
            return FakeResult([])
        model = statement.column_descriptions[0]["entity"]
        if model is OsvPackageQueryCache:
            return FakeResult(self.caches.values())
        if model is OsvNormalizedEvidence:
            return FakeResult(self.evidence.values())
        raise AssertionError(f"unexpected SQLAlchemy select: {model}")

    def add(self, row):
        if isinstance(row, OsvPackageQueryCache):
            self.caches[row.cache_key] = row
        elif isinstance(row, OsvNormalizedEvidence):
            self.evidence[(row.normalized_result_id, row.identity_key)] = row
        else:
            raise AssertionError(f"unexpected ORM row: {type(row).__name__}")

    async def flush(self):
        for index, row in enumerate(self.caches.values(), start=1):
            if row.id is None:
                row.id = index
        for index, row in enumerate(self.evidence.values(), start=1):
            if row.id is None:
                row.id = index


def fake_session_factory(session):
    return lambda: session


async def no_sleep(_seconds: float) -> None:
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_single_query_uses_exact_package_version_and_records_response_hash():
    request_log = []
    body_bytes = b'{"vulns":[{"id":"GHSA-test-1234","aliases":["CVE-2024-12345"],"summary":"advisory"}]}'

    async def handler(request: httpx.Request) -> httpx.Response:
        request_log.append(request)
        return httpx.Response(200, content=body_bytes, headers={"Content-Type": "application/json"})

    identities, status = extract_package_identities({
        "package_identity": {"ecosystem": "PyPI", "name": "demo-pkg", "version": "1.2.3"}
    })
    assert status == "ready"
    client = OSVClient(
        base_url="https://osv.test",
        rate_limit_per_second=0,
        max_retries=0,
        transport=httpx.MockTransport(handler),
        sleep=no_sleep,
    )
    try:
        results = await client.lookup(identities)
    finally:
        await client.aclose()

    assert len(request_log) == 1
    assert request_log[0].method == "POST"
    assert request_log[0].url.path == "/v1/query"
    assert request_log[0].read() == (
        b'{"package":{"name":"demo-pkg","ecosystem":"PyPI"},"version":"1.2.3"}'
    )
    assert results[0].status == "complete"
    assert results[0].raw_response_sha256 == hashlib.sha256(body_bytes).hexdigest()
    assert results[0].vulnerabilities[0]["id"] == "GHSA-test-1234"


@pytest.mark.asyncio
async def test_querybatch_preserves_input_result_order_and_purl_contract():
    request_log = []

    async def handler(request: httpx.Request) -> httpx.Response:
        request_log.append(request)
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "OSV-A"}]}, {"vulns": []}]})

    identities, status = extract_package_identities({
        "package_identities": [
            "pkg:npm/%40scope%2Fdemo@1.0.0",
            {"ecosystem": "Go", "name": "example.org/demo", "version": "2.0.0"},
        ]
    })
    assert status == "ready"
    client = OSVClient(
        base_url="https://osv.test", rate_limit_per_second=0, max_retries=0,
        transport=httpx.MockTransport(handler), sleep=no_sleep,
    )
    try:
        results = await client.lookup(identities)
    finally:
        await client.aclose()

    assert request_log[0].url.path == "/v1/querybatch"
    assert request_log[0].read() == (
        b'{"queries":[{"package":{"purl":"pkg:npm/%40scope%2Fdemo@1.0.0"}},'
        b'{"package":{"name":"example.org/demo","ecosystem":"Go"},"version":"2.0.0"}]}'
    )
    assert [row.status for row in results] == ["complete", "no_match"]
    assert results[0].vulnerabilities[0]["id"] == "OSV-A"


@pytest.mark.asyncio
async def test_querybatch_follows_only_paginated_items_and_accepts_omitted_empty_vulns():
    requests = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(200, json={
                "results": [
                    {"vulns": [{"id": "OSV-PAGE-1"}], "next_page_token": "next-1"},
                    {},
                ]
            })
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "OSV-PAGE-2"}]}]})

    identities, status = extract_package_identities({
        "package_identities": [
            {"ecosystem": "npm", "name": "demo-a", "version": "1.0"},
            {"ecosystem": "npm", "name": "demo-b", "version": "1.0"},
        ]
    })
    assert status == "ready"
    client = OSVClient(
        base_url="https://osv.test", rate_limit_per_second=0, max_retries=0,
        transport=httpx.MockTransport(handler), sleep=no_sleep,
    )
    try:
        results = await client.lookup(identities)
    finally:
        await client.aclose()

    assert len(requests) == 2
    assert requests[1].read() == (
        b'{"queries":[{"package":{"name":"demo-a","ecosystem":"npm"},'
        b'"version":"1.0","page_token":"next-1"}]}'
    )
    assert results[0].status == "complete"
    assert [item["id"] for item in results[0].vulnerabilities] == ["OSV-PAGE-1", "OSV-PAGE-2"]
    assert results[1].status == "no_match"


@pytest.mark.asyncio
async def test_single_query_omitted_vulns_field_means_no_match_not_no_vulnerability_proof():
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    identities, _ = extract_package_identities({
        "package_identity": {"ecosystem": "PyPI", "name": "demo", "version": "0.1"}
    })
    client = OSVClient(
        base_url="https://osv.test", rate_limit_per_second=0, max_retries=0,
        transport=httpx.MockTransport(handler), sleep=no_sleep,
    )
    try:
        result = (await client.lookup(identities))[0]
    finally:
        await client.aclose()

    assert result.status == "no_match"
    assert result.summary()["result_semantics"] == "no_match_is_not_proof_of_no_vulnerability"
    assert result.vulnerabilities == ()


@pytest.mark.asyncio
async def test_transient_server_error_retries_then_succeeds():
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(503, content=b"temporarily unavailable")
        return httpx.Response(200, json={"vulns": []})

    identities, _ = extract_package_identities({
        "package": {"ecosystem": "npm", "name": "demo", "version": "1.0.0"}
    })
    client = OSVClient(
        base_url="https://osv.test", rate_limit_per_second=0, max_retries=1,
        transport=httpx.MockTransport(handler), sleep=no_sleep,
    )
    try:
        result = (await client.lookup(identities))[0]
    finally:
        await client.aclose()

    assert calls == 2
    assert result.status == "no_match"


@pytest.mark.asyncio
async def test_timeout_is_retried_with_a_bounded_attempt_count_then_marked_failed():
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ReadTimeout("mock timeout", request=request)

    identities, _ = extract_package_identities({
        "package_identity": {"ecosystem": "npm", "name": "demo", "version": "1.0"}
    })
    client = OSVClient(
        base_url="https://osv.test", rate_limit_per_second=0, max_retries=1,
        transport=httpx.MockTransport(handler), sleep=no_sleep,
    )
    try:
        result = (await client.lookup(identities))[0]
    finally:
        await client.aclose()

    assert calls == 2
    assert result.status == "failed"
    assert result.error_code == "timeout"


@pytest.mark.asyncio
async def test_non_retryable_http_failure_and_invalid_schema_fail_closed():
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/query":
            return httpx.Response(400, content=b"bad identity")
        return httpx.Response(200, json={"not_results": []})

    identities, _ = extract_package_identities({
        "package_identities": [
            {"ecosystem": "npm", "name": "demo-a", "version": "1.0"},
            {"ecosystem": "npm", "name": "demo-b", "version": "1.0"},
        ]
    })
    client = OSVClient(
        base_url="https://osv.test", rate_limit_per_second=0, max_retries=0,
        transport=httpx.MockTransport(handler), sleep=no_sleep,
    )
    try:
        results = await client.lookup(identities)
    finally:
        await client.aclose()

    assert [row.status for row in results] == ["failed", "failed"]
    assert {row.error_code for row in results} == {"invalid_batch_result_count"}


def test_untrusted_osv_candidate_remains_separate_from_confirmed_cve_summary():
    context = build_enrichment_context(
        cve_summary=None,
        osv_context={
            "status": "complete",
            "vulnerability_count": 1,
            "vulnerabilities": [{"id": "GHSA-test"}],
            "evidence_refs": [{"ref": "normalized_results:4", "response_sha256": "a" * 64}],
            "trust": "untrusted_external_advisory",
        },
    )

    assert context["schema"] == "m2a-enrichment-context-v1"
    assert context["cve"]["status"] == "not_evaluated"
    assert context["osv"]["status"] == "complete"
    assert context["osv"]["trust"] == "untrusted_external_advisory"


@pytest.mark.asyncio
async def test_enrichment_persists_query_and_evidence_then_uses_cache_without_second_request():
    normalized = NormalizedResult(
        id=41,
        normalized_output={"package_identity": {"ecosystem": "PyPI", "name": "demo", "version": "1.2.3"}},
    )
    session = FakeSession(normalized)
    client = AsyncMock()
    client.lookup.return_value = [OSVLookup(
        "complete",
        ({"id": "GHSA-test", "aliases": ["CVE-2024-12345"]},),
        "c" * 64,
        1.0,
    )]
    now = datetime.now(timezone.utc)

    context = await enrich_normalized_result(
        41, enabled=True, client=client, session_factory=fake_session_factory(session), now=now,
    )
    repeated = await enrich_normalized_result(
        41, enabled=True, client=client, session_factory=fake_session_factory(session), now=now + timedelta(seconds=1),
    )

    client.lookup.assert_awaited_once()
    cache = next(iter(session.caches.values()))
    evidence = next(iter(session.evidence.values()))
    assert cache.status == "complete"
    assert cache.response_sha256 == "c" * 64
    assert cache.attempt_count == 1
    assert evidence.status == "complete"
    assert evidence.evidence_ref == "normalized_results:41"
    assert context["cve_aliases"] == ["CVE-2024-12345"]
    assert repeated["status"] == "complete"


@pytest.mark.asyncio
async def test_failed_cache_refresh_preserves_prior_result_and_records_failed_response_hash():
    normalized = NormalizedResult(
        id=51,
        normalized_output={"package_identity": {"ecosystem": "npm", "name": "demo", "version": "1.0.0"}},
    )
    session = FakeSession(normalized)
    identities, _ = extract_package_identities(normalized.normalized_output)
    old_summary = {
        "vulnerability_count": 1,
        "vulnerabilities": [{"id": "GHSA-old", "aliases": []}],
        "cve_aliases": [],
        "truncated": False,
    }
    old_time = datetime.now(timezone.utc) - timedelta(days=2)
    cache = OsvPackageQueryCache(
        id=1, cache_key=identities[0].cache_key, ecosystem="npm", package_name="demo", package_version="1.0.0",
        status="complete", source="OSV", retrieved_at=old_time, expires_at=old_time,
        response_sha256="a" * 64, response_summary=old_summary, match_confidence=1.0, attempt_count=1,
        created_at=old_time, updated_at=old_time,
    )
    evidence = OsvNormalizedEvidence(
        id=1, normalized_result_id=51, identity_key=identities[0].cache_key, cache_id=1,
        package_identity=identities[0].as_dict(), status="complete", source="OSV", retrieved_at=old_time,
        response_sha256="a" * 64, match_confidence=1.0, evidence_ref="normalized_results:51",
        result_summary=old_summary, created_at=old_time, updated_at=old_time,
    )
    session.add(cache)
    session.add(evidence)
    client = AsyncMock()
    client.lookup.return_value = [OSVLookup("failed", raw_response_sha256="d" * 64, error_code="timeout")]

    context = await enrich_normalized_result(
        51, enabled=True, client=client, session_factory=fake_session_factory(session), now=datetime.now(timezone.utc),
    )

    assert cache.status == "complete"
    assert cache.response_summary == old_summary
    assert cache.response_sha256 == "a" * 64
    assert cache.last_attempt_sha256 == "d" * 64
    assert evidence.status == "stale"
    assert evidence.response_sha256 == "a" * 64
    assert evidence.last_attempt_sha256 == "d" * 64
    assert context["status"] == "partial"
    assert context["package_states"][0]["error_code"] == "timeout"
