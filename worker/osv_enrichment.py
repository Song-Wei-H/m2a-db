"""OSV online adapter and normalized-evidence enrichment persistence.

Network I/O is injectable for tests and happens only after the NormalizedResult
has committed. Lookup results are external advisory evidence, never execution
authority and never proof that a target is exploitable.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Sequence

import httpx
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import async_session
from app.models import NormalizedResult, OsvNormalizedEvidence, OsvPackageQueryCache
from worker.package_identity import PackageIdentity, extract_package_identities

logger = logging.getLogger(__name__)

OSV_SOURCE = "OSV"
MAX_ADVISORIES_PER_QUERY = 250
MAX_PAGES = 4
MAX_BATCH_QUERIES = 1000
MAX_RETRY_AFTER_SECONDS = 10.0
MAX_SUMMARY_LENGTH = 500
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_PROCESS_RATE_LOCK = threading.Lock()
_PROCESS_NEXT_REQUEST_AT = 0.0


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _safe_text(value: Any, *, limit: int = MAX_SUMMARY_LENGTH) -> str | None:
    if not isinstance(value, str):
        return None
    value = _CONTROL_RE.sub(" ", value).strip()
    return value[:limit] or None


@dataclass(frozen=True)
class OSVLookup:
    status: str
    vulnerabilities: tuple[dict[str, Any], ...] = ()
    raw_response_sha256: str | None = None
    match_confidence: float = 1.0
    error_code: str | None = None

    def summary(self) -> dict[str, Any]:
        aliases = sorted({
            alias
            for row in self.vulnerabilities
            for alias in row.get("aliases", [])
            if isinstance(alias, str) and _CVE_RE.fullmatch(alias)
        })
        return {
            "status": self.status,
            "vulnerability_count": len(self.vulnerabilities),
            "vulnerabilities": [dict(row) for row in self.vulnerabilities[:MAX_ADVISORIES_PER_QUERY]],
            "cve_aliases": aliases[:MAX_ADVISORIES_PER_QUERY],
            "truncated": len(self.vulnerabilities) > MAX_ADVISORIES_PER_QUERY,
            "result_semantics": "no_match_is_not_proof_of_no_vulnerability",
            "validation_status": "candidate_requires_independent_validation",
            "trust": "untrusted_external_advisory",
        }


class OSVClient:
    """Bounded OSV v1/query and v1/querybatch client with injectable transport."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        timeout_seconds: float | None = None,
        max_retries: int | None = None,
        rate_limit_per_second: float | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Any] = asyncio.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.base_url = (base_url or settings.osv_api_base_url).rstrip("/")
        self.timeout_seconds = max(0.1, timeout_seconds or settings.osv_timeout_seconds)
        self.max_retries = max(0, min(5, settings.osv_max_retries if max_retries is None else max_retries))
        self.rate_limit_per_second = max(
            0.0,
            rate_limit_per_second if rate_limit_per_second is not None else settings.osv_rate_limit_per_second,
        )
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(self.timeout_seconds),
            trust_env=False,
            follow_redirects=False,
            transport=transport,
            headers={"Accept": "application/json", "Content-Type": "application/json", "User-Agent": "m2a-osv-enrichment/1.0"},
        )
        self._sleep = sleep
        self._monotonic = monotonic
        self._semaphore = asyncio.Semaphore(2)

    async def aclose(self) -> None:
        await self._client.aclose()

    @staticmethod
    def _query_payload(identity: PackageIdentity) -> dict[str, Any]:
        if identity.purl:
            # OSV rejects a versioned PURL together with top-level version.
            return {"package": {"purl": identity.purl}}
        return {
            "package": {"name": identity.name, "ecosystem": identity.ecosystem},
            "version": identity.version,
        }

    async def _pace(self) -> None:
        global _PROCESS_NEXT_REQUEST_AT
        if self.rate_limit_per_second <= 0:
            return
        interval = 1.0 / self.rate_limit_per_second
        with _PROCESS_RATE_LOCK:
            now = self._monotonic()
            wait_for = max(0.0, _PROCESS_NEXT_REQUEST_AT - now)
            _PROCESS_NEXT_REQUEST_AT = max(now, _PROCESS_NEXT_REQUEST_AT) + interval
        if wait_for > 0:
            await self._sleep(wait_for)

    async def _post_json(self, path: str, payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None, bytes | None]:
        for attempt in range(self.max_retries + 1):
            try:
                async with self._semaphore:
                    await self._pace()
                    response = await self._client.post(path, json=payload)
                if response.status_code == 429 or 500 <= response.status_code <= 599:
                    if attempt < self.max_retries:
                        retry_after = response.headers.get("Retry-After")
                        try:
                            delay = float(retry_after) if retry_after is not None else 0.25 * (2**attempt)
                        except ValueError:
                            delay = 0.25 * (2**attempt)
                        await self._sleep(min(MAX_RETRY_AFTER_SECONDS, max(0.0, delay)))
                        continue
                    return None, "http_429" if response.status_code == 429 else "http_5xx", response.content
                if response.status_code < 200 or response.status_code >= 300:
                    return None, f"http_{response.status_code}", response.content
                try:
                    body = response.json()
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return None, "invalid_json", response.content
                if not isinstance(body, dict):
                    return None, "invalid_response_schema", response.content
                return body, None, response.content
            except httpx.TimeoutException:
                error_code = "timeout"
            except httpx.TransportError:
                error_code = "transport_error"
            if attempt < self.max_retries:
                await self._sleep(min(MAX_RETRY_AFTER_SECONDS, 0.25 * (2**attempt)))
                continue
            return None, error_code, None
        return None, "retry_exhausted", None

    @staticmethod
    def _summarize_vulnerabilities(rows: Any) -> tuple[list[dict[str, Any]], bool]:
        if not isinstance(rows, list):
            raise ValueError("vulns must be an array")
        summary: list[dict[str, Any]] = []
        incomplete = False
        for row in rows:
            if not isinstance(row, dict):
                incomplete = True
                continue
            osv_id = _safe_text(row.get("id"), limit=128)
            if not osv_id:
                # Preserve that a record existed, without inventing an ID.
                incomplete = True
                continue
            aliases = row.get("aliases") if isinstance(row.get("aliases"), list) else []
            summary.append({
                "id": osv_id,
                "aliases": [v[:128] for v in aliases if isinstance(v, str) and len(v) <= 128][:32],
                "modified": _safe_text(row.get("modified"), limit=80),
                "summary": _safe_text(row.get("summary"), limit=MAX_SUMMARY_LENGTH),
            })
        return summary, incomplete

    @staticmethod
    def _result_lookup(body: dict[str, Any], raw_parts: Sequence[bytes | None]) -> OSVLookup:
        raw_hash = hashlib.sha256(b"\n--osv-page--\n".join(part or b"" for part in raw_parts)).hexdigest()
        # OSV's schema permits the repeated vulns field to be omitted when it
        # is empty. An explicit null or a non-array remains invalid.
        vulns = body.get("vulns", [])
        try:
            summary, incomplete = OSVClient._summarize_vulnerabilities(vulns)
        except ValueError:
            return OSVLookup("failed", raw_response_sha256=raw_hash, error_code="invalid_vulns_schema")
        paginated = bool(body.get("next_page_token"))
        status = "partial" if paginated or incomplete else ("complete" if summary else "no_match")
        error_code = "pagination_limit_reached" if paginated else "unidentified_advisory_record" if incomplete else None
        return OSVLookup(status, tuple(summary), raw_hash, 1.0, error_code)

    async def _query_one(self, identity: PackageIdentity) -> OSVLookup:
        payload = self._query_payload(identity)
        raw_parts: list[bytes | None] = []
        all_rows: list[dict[str, Any]] = []
        page_token: str | None = None
        for _ in range(MAX_PAGES):
            page_payload = {**payload, **({"page_token": page_token} if page_token else {})}
            body, error, raw = await self._post_json("/v1/query", page_payload)
            raw_parts.append(raw)
            if error or body is None:
                raw_hash = hashlib.sha256(b"\n--osv-page--\n".join(part or b"" for part in raw_parts)).hexdigest()
                return OSVLookup("failed", tuple(all_rows), raw_hash, 1.0, error)
            vulns = body.get("vulns", [])
            if not isinstance(vulns, list):
                raw_hash = hashlib.sha256(b"\n--osv-page--\n".join(part or b"" for part in raw_parts)).hexdigest()
                return OSVLookup("failed", tuple(all_rows), raw_hash, 1.0, "invalid_vulns_schema")
            rows, incomplete = self._summarize_vulnerabilities(vulns)
            all_rows.extend(rows)
            page_token = body.get("next_page_token") if isinstance(body.get("next_page_token"), str) else None
            if incomplete:
                raw_hash = hashlib.sha256(b"\n--osv-page--\n".join(part or b"" for part in raw_parts)).hexdigest()
                return OSVLookup("partial", tuple(all_rows), raw_hash, 1.0, "unidentified_advisory_record")
            if not page_token:
                raw_hash = hashlib.sha256(b"\n--osv-page--\n".join(part or b"" for part in raw_parts)).hexdigest()
                status = "complete" if all_rows else "no_match"
                return OSVLookup(status, tuple(all_rows), raw_hash)
        raw_hash = hashlib.sha256(b"\n--osv-page--\n".join(part or b"" for part in raw_parts)).hexdigest()
        return OSVLookup("partial", tuple(all_rows), raw_hash, 1.0, "pagination_limit_reached")

    async def lookup(self, identities: Sequence[PackageIdentity]) -> list[OSVLookup]:
        if not identities:
            return []
        if len(identities) == 1:
            return [await self._query_one(identities[0])]
        if len(identities) > MAX_BATCH_QUERIES:
            results: list[OSVLookup] = []
            for offset in range(0, len(identities), MAX_BATCH_QUERIES):
                results.extend(await self.lookup(identities[offset:offset + MAX_BATCH_QUERIES]))
            return results

        base_queries = [self._query_payload(identity) for identity in identities]
        rows_by_index: list[list[dict[str, Any]]] = [[] for _ in identities]
        incomplete_by_index = [False for _ in identities]
        error_by_index: list[str | None] = [None for _ in identities]
        pending_tokens: dict[int, str | None] = {index: None for index in range(len(identities))}
        raw_parts: list[bytes | None] = []

        for page_number in range(MAX_PAGES):
            query_indices = list(pending_tokens)
            queries = []
            for index in query_indices:
                query = dict(base_queries[index])
                page_token = pending_tokens[index]
                if page_token:
                    query["page_token"] = page_token
                queries.append(query)
            body, error, raw = await self._post_json("/v1/querybatch", {"queries": queries})
            raw_parts.append(raw)
            if error or body is None:
                for index in query_indices:
                    error_by_index[index] = error or "invalid_response"
                pending_tokens.clear()
                break

            results = body.get("results")
            if not isinstance(results, list) or len(results) != len(query_indices):
                for index in query_indices:
                    error_by_index[index] = "invalid_batch_result_count"
                pending_tokens.clear()
                break

            next_tokens: dict[int, str | None] = {}
            for index, item in zip(query_indices, results, strict=True):
                if not isinstance(item, dict):
                    error_by_index[index] = "invalid_batch_result_schema"
                    continue
                vulns = item.get("vulns", [])
                if not isinstance(vulns, list):
                    error_by_index[index] = "invalid_vulns_schema"
                    continue
                rows, incomplete = self._summarize_vulnerabilities(vulns)
                rows_by_index[index].extend(rows)
                incomplete_by_index[index] = incomplete_by_index[index] or incomplete
                page_token = item.get("next_page_token")
                if isinstance(page_token, str) and page_token:
                    next_tokens[index] = page_token
            pending_tokens = next_tokens
            if not pending_tokens:
                break

        raw_hash = hashlib.sha256(b"\n--osv-page--\n".join(part or b"" for part in raw_parts)).hexdigest()
        lookups: list[OSVLookup] = []
        for index, rows in enumerate(rows_by_index):
            error = error_by_index[index]
            has_more = index in pending_tokens
            if error:
                status = "partial" if rows else "failed"
                lookups.append(OSVLookup(status, tuple(rows), raw_hash, 1.0, error))
            elif has_more:
                lookups.append(OSVLookup("partial", tuple(rows), raw_hash, 1.0, "pagination_limit_reached"))
            elif incomplete_by_index[index]:
                lookups.append(OSVLookup("partial", tuple(rows), raw_hash, 1.0, "unidentified_advisory_record"))
            else:
                lookups.append(OSVLookup("complete" if rows else "no_match", tuple(rows), raw_hash))
        return lookups


def _identity_from_json(value: dict[str, Any]) -> PackageIdentity | None:
    identities, status = extract_package_identities({"package_identity": value})
    return identities[0] if status == "ready" and len(identities) == 1 else None


def _cache_summary(cache: OsvPackageQueryCache) -> dict[str, Any]:
    summary = cache.response_summary or {}
    return {
        "status": cache.status,
        "vulnerability_count": int(summary.get("vulnerability_count", 0) or 0),
        "vulnerabilities": summary.get("vulnerabilities", []) if isinstance(summary.get("vulnerabilities"), list) else [],
        "cve_aliases": summary.get("cve_aliases", []) if isinstance(summary.get("cve_aliases"), list) else [],
        "truncated": bool(summary.get("truncated")),
        "validation_status": "candidate_requires_independent_validation",
        "trust": "untrusted_external_advisory",
    }


async def enrich_normalized_result(
    normalized_result_id: int,
    *,
    enabled: bool | None = None,
    client: OSVClient | None = None,
    session_factory: Callable[..., Any] = async_session,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Persist query state and enrich one already-committed NormalizedResult.

    The NormalizedResult transaction completes before OSV network I/O begins.
    A pending row acts as an idempotency/claim marker; transient refresh errors
    never erase a prior successful cache value.
    """
    if enabled is None:
        enabled = settings.osv_enrichment_enabled
    if not enabled:
        return {
            "schema": "m2a-enrichment-context-v1",
            "cve": {"status": "not_requested"},
            "osv": {"status": "disabled", "vulnerability_count": 0, "evidence_refs": []},
        }

    current = now or utcnow()
    queries_to_run: list[tuple[PackageIdentity, int, dict[str, Any] | None, str | None]] = []
    async with session_factory() as session:
        async with session.begin():
            normalized = await session.get(NormalizedResult, normalized_result_id)
            if normalized is None:
                raise ValueError(f"normalized_result_id={normalized_result_id} not found")
            identities, identity_status = extract_package_identities(normalized.normalized_output)
            evidence_ref = f"normalized_results:{normalized.id}"
            if not identities:
                key = hashlib.sha256(f"unsupported:{normalized.id}".encode()).hexdigest()
                row_result = await session.execute(select(OsvNormalizedEvidence).where(
                    OsvNormalizedEvidence.normalized_result_id == normalized.id,
                    OsvNormalizedEvidence.identity_key == key,
                ))
                row = row_result.scalar_one_or_none()
                values = {
                    "normalized_result_id": normalized.id,
                    "identity_key": key,
                    "cache_id": None,
                    "package_identity": None,
                    "status": "unsupported",
                    "source": OSV_SOURCE,
                    "retrieved_at": None,
                    "response_sha256": None,
                    "match_confidence": None,
                    "evidence_ref": evidence_ref,
                    "result_summary": {"status": "unsupported", "identity_status": identity_status},
                    "error_code": "package_identity_missing" if identity_status == "not_provided" else "package_identity_unsupported",
                    "updated_at": current,
                }
                if row is None:
                    row = OsvNormalizedEvidence(**values, created_at=current)
                    session.add(row)
                else:
                    for key_name, value in values.items():
                        setattr(row, key_name, value)
            else:
                # Lock package identities in a stable order. A transaction-level
                # advisory lock closes the missing-row race that SELECT FOR UPDATE
                # cannot prevent when concurrent callers create the first cache row.
                for identity in sorted(identities, key=lambda item: item.cache_key):
                    await session.execute(
                        text("SELECT pg_advisory_xact_lock(hashtextextended(:cache_key, 0))"),
                        {"cache_key": identity.cache_key},
                    )
                    cache_result = await session.execute(select(OsvPackageQueryCache).where(
                        OsvPackageQueryCache.cache_key == identity.cache_key
                    ).with_for_update())
                    cache = cache_result.scalar_one_or_none()
                    evidence_result = await session.execute(select(OsvNormalizedEvidence).where(
                        OsvNormalizedEvidence.normalized_result_id == normalized.id,
                        OsvNormalizedEvidence.identity_key == identity.cache_key,
                    ))
                    evidence_row = evidence_result.scalar_one_or_none()
                    if cache and cache.status in {"complete", "no_match", "partial"} and cache.expires_at and cache.expires_at > current:
                        summary = _cache_summary(cache)
                        if evidence_row is None:
                            evidence_row = OsvNormalizedEvidence(
                                normalized_result_id=normalized.id,
                                identity_key=identity.cache_key,
                                cache_id=cache.id,
                                package_identity=identity.as_dict(),
                                status=cache.status,
                                source=OSV_SOURCE,
                                retrieved_at=cache.retrieved_at,
                                response_sha256=cache.response_sha256,
                                match_confidence=cache.match_confidence,
                                evidence_ref=evidence_ref,
                                result_summary=summary,
                                error_code=None,
                                created_at=current,
                                updated_at=current,
                            )
                            session.add(evidence_row)
                        else:
                            evidence_row.cache_id = cache.id
                            evidence_row.package_identity = identity.as_dict()
                            evidence_row.status = cache.status
                            evidence_row.source = OSV_SOURCE
                            evidence_row.retrieved_at = cache.retrieved_at
                            evidence_row.response_sha256 = cache.response_sha256
                            evidence_row.match_confidence = cache.match_confidence
                            evidence_row.evidence_ref = evidence_ref
                            evidence_row.result_summary = summary
                            evidence_row.error_code = None
                            evidence_row.updated_at = current
                        continue

                    if cache and cache.retry_after and cache.retry_after > current:
                        stale = cache.response_summary is not None
                        status = "stale" if stale else ("pending" if cache.status == "pending" else "failed")
                        summary = _cache_summary(cache) if stale else {"status": status, "vulnerability_count": 0, "vulnerabilities": []}
                        if evidence_row is None:
                            evidence_row = OsvNormalizedEvidence(
                                normalized_result_id=normalized.id, identity_key=identity.cache_key,
                                cache_id=cache.id, package_identity=identity.as_dict(), status=status,
                                source=OSV_SOURCE, retrieved_at=cache.retrieved_at,
                                response_sha256=cache.response_sha256, match_confidence=cache.match_confidence,
                                evidence_ref=evidence_ref, result_summary=summary, error_code=cache.error_code,
                                created_at=current, updated_at=current,
                            )
                            session.add(evidence_row)
                        else:
                            evidence_row.cache_id = cache.id
                            evidence_row.package_identity = identity.as_dict()
                            evidence_row.status = status
                            evidence_row.result_summary = summary
                            evidence_row.error_code = cache.error_code
                            evidence_row.updated_at = current
                        continue

                    if cache and cache.status == "pending" and cache.updated_at and cache.updated_at > current - timedelta(minutes=5):
                        if evidence_row is None:
                            evidence_row = OsvNormalizedEvidence(
                                normalized_result_id=normalized.id, identity_key=identity.cache_key,
                                cache_id=cache.id, package_identity=identity.as_dict(), status="pending",
                                source=OSV_SOURCE, evidence_ref=evidence_ref,
                                result_summary={"status": "pending", "vulnerability_count": 0, "vulnerabilities": []},
                                created_at=current, updated_at=current,
                            )
                            session.add(evidence_row)
                        continue

                    prior_summary = cache.response_summary if cache else None
                    prior_status = cache.status if cache else None
                    if cache is None:
                        cache = OsvPackageQueryCache(
                            cache_key=identity.cache_key,
                            ecosystem=identity.ecosystem,
                            package_name=identity.name,
                            package_version=identity.version,
                            status="pending",
                            source=OSV_SOURCE,
                            attempt_count=1,
                            created_at=current,
                            updated_at=current,
                        )
                        session.add(cache)
                        await session.flush()
                    else:
                        cache.status = "pending"
                        cache.error_code = None
                        cache.retry_after = None
                        cache.attempt_count = int(cache.attempt_count or 0) + 1
                        cache.updated_at = current

                    if evidence_row is None:
                        evidence_row = OsvNormalizedEvidence(
                            normalized_result_id=normalized.id,
                            identity_key=identity.cache_key,
                            cache_id=cache.id,
                            package_identity=identity.as_dict(),
                            status="pending",
                            source=OSV_SOURCE,
                            evidence_ref=evidence_ref,
                            result_summary={"status": "pending", "vulnerability_count": 0, "vulnerabilities": []},
                            created_at=current,
                            updated_at=current,
                        )
                        session.add(evidence_row)
                    else:
                        evidence_row.cache_id = cache.id
                        evidence_row.package_identity = identity.as_dict()
                        evidence_row.status = "pending"
                        evidence_row.source = OSV_SOURCE
                        evidence_row.evidence_ref = evidence_ref
                        evidence_row.result_summary = {"status": "pending", "vulnerability_count": 0, "vulnerabilities": []}
                        evidence_row.updated_at = current
                    queries_to_run.append((identity, cache.id, prior_summary, prior_status))

    if queries_to_run:
        own_client = client is None
        osv_client = client or OSVClient()
        try:
            lookups = await osv_client.lookup([item[0] for item in queries_to_run])
        except Exception:
            logger.exception("OSV adapter failed for normalized_result_id=%s", normalized_result_id)
            lookups = [OSVLookup("failed", error_code="adapter_error") for _ in queries_to_run]
        finally:
            if own_client:
                await osv_client.aclose()

        async with session_factory() as session:
            async with session.begin():
                for (identity, cache_id, prior_summary, prior_status), lookup in zip(queries_to_run, lookups, strict=True):
                    cache = await session.get(OsvPackageQueryCache, cache_id)
                    evidence_result = await session.execute(select(OsvNormalizedEvidence).where(
                        OsvNormalizedEvidence.normalized_result_id == normalized_result_id,
                        OsvNormalizedEvidence.identity_key == identity.cache_key,
                    ))
                    evidence_row = evidence_result.scalar_one_or_none()
                    if cache is None or evidence_row is None:
                        raise RuntimeError("OSV query claim disappeared before persistence")
                    if lookup.status in {"complete", "no_match", "partial"}:
                        response_summary = lookup.summary()
                        cache.status = lookup.status
                        cache.source = OSV_SOURCE
                        cache.retrieved_at = current
                        cache.expires_at = current + timedelta(seconds=max(60, settings.osv_cache_ttl_seconds))
                        cache.retry_after = None
                        cache.response_sha256 = lookup.raw_response_sha256
                        cache.last_attempt_sha256 = lookup.raw_response_sha256
                        cache.response_summary = response_summary
                        cache.match_confidence = lookup.match_confidence
                        cache.error_code = lookup.error_code
                        evidence_row.status = lookup.status
                        evidence_row.retrieved_at = current
                        evidence_row.response_sha256 = lookup.raw_response_sha256
                        evidence_row.last_attempt_sha256 = lookup.raw_response_sha256
                        evidence_row.match_confidence = lookup.match_confidence
                        evidence_row.result_summary = response_summary
                        evidence_row.error_code = lookup.error_code
                    else:
                        # Keep prior successful bytes/metadata and only expose a
                        # refresh failure state; outages never become no-match.
                        cache.error_code = lookup.error_code or "lookup_failed"
                        cache.last_attempt_sha256 = lookup.raw_response_sha256
                        cache.retry_after = current + timedelta(seconds=max(1, settings.osv_retry_cooldown_seconds))
                        cache.updated_at = current
                        evidence_row.last_attempt_sha256 = lookup.raw_response_sha256
                        has_prior = (
                            prior_status in {"complete", "no_match", "partial"}
                            and prior_summary is not None
                            and cache.response_sha256 is not None
                        )
                        if has_prior:
                            cache.status = prior_status
                            evidence_row.status = "stale"
                            evidence_row.result_summary = prior_summary
                            evidence_row.response_sha256 = cache.response_sha256
                            evidence_row.retrieved_at = cache.retrieved_at
                            evidence_row.match_confidence = cache.match_confidence
                        else:
                            cache.status = "failed"
                            evidence_row.status = "failed"
                            evidence_row.result_summary = {"status": "failed", "vulnerability_count": 0, "vulnerabilities": []}
                            evidence_row.response_sha256 = None
                            evidence_row.last_attempt_sha256 = lookup.raw_response_sha256
                        evidence_row.error_code = cache.error_code
                    cache.updated_at = current
                    evidence_row.updated_at = current

    return await get_osv_context_for_normalized_result(normalized_result_id, session_factory=session_factory)


async def get_osv_context_for_normalized_result(
    normalized_result_id: int,
    *,
    session_factory: Callable[..., Any] = async_session,
) -> dict[str, Any]:
    async with session_factory() as session:
        rows = list((await session.execute(select(OsvNormalizedEvidence).where(
            OsvNormalizedEvidence.normalized_result_id == normalized_result_id
        ).order_by(OsvNormalizedEvidence.id))).scalars().all())
    states = []
    for row in rows:
        summary = row.result_summary or {}
        states.append({
            "status": row.status,
            "vulnerability_count": summary.get("vulnerability_count", 0),
            "vulnerabilities": summary.get("vulnerabilities", []),
            "cve_aliases": summary.get("cve_aliases", []),
            "evidence_ref": row.evidence_ref,
            "response_sha256": row.response_sha256,
            "last_attempt_sha256": row.last_attempt_sha256,
            "retrieved_at": row.retrieved_at.isoformat() if row.retrieved_at else None,
            "match_confidence": row.match_confidence,
            "error_code": row.error_code,
            "package_identity": row.package_identity,
        })

    statuses = {str(row.get("status", "unknown")) for row in states}
    if not states:
        status = "not_requested"
    elif statuses <= {"complete", "no_match"}:
        status = "complete" if "complete" in statuses else "no_match"
    elif statuses == {"unsupported"}:
        status = "unsupported"
    elif statuses == {"disabled"}:
        status = "disabled"
    elif statuses == {"failed"}:
        status = "failed"
    elif statuses == {"pending"}:
        status = "pending"
    else:
        status = "partial"
    vulnerabilities = [
        vulnerability
        for row in states
        for vulnerability in (row.get("vulnerabilities") or [])
        if isinstance(vulnerability, dict)
    ]
    aliases = sorted({
        alias
        for row in states
        for alias in (row.get("cve_aliases") or [])
        if isinstance(alias, str) and _CVE_RE.fullmatch(alias)
    })
    return {
        "status": status,
        "vulnerability_count": sum(int(row.get("vulnerability_count") or 0) for row in states),
        "vulnerabilities": vulnerabilities[:MAX_ADVISORIES_PER_QUERY],
        "cve_aliases": aliases[:MAX_ADVISORIES_PER_QUERY],
        "evidence_refs": [
            {
                "ref": row.get("evidence_ref"),
                "source": OSV_SOURCE,
                "response_sha256": row.get("response_sha256"),
                "last_attempt_sha256": row.get("last_attempt_sha256"),
                "retrieved_at": row.get("retrieved_at"),
                "match_confidence": row.get("match_confidence"),
            }
            for row in states
        ],
        "package_states": states,
        "result_semantics": "no_match_is_not_proof_of_no_vulnerability",
        "validation_status": "candidate_requires_independent_validation",
        "trust": "untrusted_external_advisory",
    }


def build_enrichment_context(
    *,
    cve_summary: Any | None = None,
    osv_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if cve_summary is None:
        cve = {"status": "not_evaluated", "cve_count": 0, "max_cvss": None, "max_epss": None, "has_kev": False}
    else:
        cve = {
            "status": "available",
            "score": cve_summary.total_score,
            "best_cve": cve_summary.best_cve,
            "max_cvss": cve_summary.max_cvss,
            "max_epss": cve_summary.max_epss,
            "has_kev": cve_summary.has_kev,
            "cve_count": cve_summary.cve_count,
            "best_match_type": cve_summary.best_match_type,
            "best_match_confidence": cve_summary.best_match_confidence,
        }
    return {
        "schema": "m2a-enrichment-context-v1",
        "cve": cve,
        "osv": osv_context or {"status": "not_requested", "vulnerability_count": 0, "evidence_refs": []},
    }
