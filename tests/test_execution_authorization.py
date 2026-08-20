import asyncio
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.execution_governance import canonical_parameters, parameter_hash, propose_and_authorize, utcnow_naive
from app.action_contracts import ACTION_IDENTITIES, ACTION_TEMPLATES
from app.models import Target
from worker.task_poller import _claim_task


class ScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class GovernanceSession:
    def __init__(self, action):
        self.action = action
        self.added = []

    async def execute(self, _statement):
        return ScalarResult(self.action)

    def add(self, row):
        self.added.append(row)

    async def flush(self):
        for index, row in enumerate(self.added, 1):
            if getattr(row, "id", None) is None:
                row.id = index


@pytest.mark.asyncio
async def test_registry_tier_is_authoritative_and_tier2_auto_authorizes():
    action = SimpleNamespace(action_id="nuclei.safe_scan.v1", validation_tier=2,
        execution_identity=ACTION_IDENTITIES["nuclei.safe_scan.v1"], template_version=ACTION_TEMPLATES["nuclei.safe_scan.v1"])
    db = GovernanceSession(action)
    target = Target(id=7, target="192.0.2.7", scope="192.0.2.7/32")
    params = canonical_parameters(target=target.target, port=443, protocol="tcp", service="https", action_id="nuclei.safe_scan.v1")
    governed = await propose_and_authorize(db, target=target, tool_name="nuclei_safe",
        parameters=params, reason="caller claimed info risk", confidence=.5,
        provider="llm", authorization_source="gade-tier-policy")
    assert governed.authorization.validation_tier == 2
    assert governed.authorization.execution_limit == 1
    assert governed.authorization.parameters_hash == parameter_hash(params)


@pytest.mark.asyncio
@pytest.mark.parametrize(("tool_name", "action_id", "tier", "port", "service"), [
    ("dns_metadata", "dns.metadata_collect.v1", 0, None, "dns"),
    ("tls_certificate", "tls.certificate_collect.v1", 1, 443, "tls"),
    ("nmap_service", "nmap.service_fingerprint.v1", 1, None, None),
])
async def test_batch1_registry_tier_is_authoritative_and_auto_authorizes(
    tool_name, action_id, tier, port, service,
):
    action = SimpleNamespace(action_id=action_id, validation_tier=tier,
        execution_identity=ACTION_IDENTITIES[action_id], template_version=ACTION_TEMPLATES[action_id])
    db = GovernanceSession(action)
    target = Target(id=9, target="asset.example", scope="asset.example")
    params = canonical_parameters(target=target.target, port=port, protocol="tcp" if port else None,
                                  service=service, action_id=action_id)
    governed = await propose_and_authorize(
        db, target=target, tool_name=tool_name, parameters=params,
        reason="caller and LLM claimed a different tier", confidence=.4,
        provider="llm", authorization_source="gade-tier-policy",
    )
    assert governed.authorization.validation_tier == tier
    assert governed.authorization.execution_limit == 1


@pytest.mark.asyncio
async def test_tier3_requires_explicit_human_authorization():
    action = SimpleNamespace(action_id="nuclei.safe_scan.v1", validation_tier=3,
        execution_identity=ACTION_IDENTITIES["nuclei.safe_scan.v1"], template_version=ACTION_TEMPLATES["nuclei.safe_scan.v1"])
    db = GovernanceSession(action)
    target = Target(id=8, target="192.0.2.8", scope="192.0.2.8/32")
    params = canonical_parameters(target=target.target, port=443, protocol="tcp", service="https", action_id="nuclei.safe_scan.v1")
    governed = await propose_and_authorize(db, target=target, tool_name="nuclei_safe",
        parameters=params, reason="validation", confidence=.8, provider="decision-engine",
        authorization_source="gade-tier-policy")
    assert governed.authorization is None
    assert governed.proposal.status == "pending_human_approval"


@pytest.mark.asyncio
async def test_validation_task_without_authorization_is_not_claimed():
    task = SimpleNamespace(id=1, status="pending", approval_status="approved",
        tool_name="nuclei_safe", execution_authorization_id=None, action_id=None)
    db = MagicMock()
    db.get = AsyncMock(return_value=task)
    assert await _claim_task(db, 1) is False


@pytest.mark.asyncio
async def test_expired_consumed_target_or_action_mismatch_rejects_claim():
    task = SimpleNamespace(id=2, target_id=7, status="pending", approval_status="not_required",
        tool_name="nuclei_safe", execution_authorization_id=4, action_id="nuclei.safe_scan.v1")
    cases = [
        SimpleNamespace(target_id=8, action_id=task.action_id, expires_at=utcnow_naive()+timedelta(minutes=1), consumed_count=0, execution_limit=1),
        SimpleNamespace(target_id=7, action_id="other", expires_at=utcnow_naive()+timedelta(minutes=1), consumed_count=0, execution_limit=1),
        SimpleNamespace(target_id=7, action_id=task.action_id, expires_at=utcnow_naive()-timedelta(seconds=1), consumed_count=0, execution_limit=1),
        SimpleNamespace(target_id=7, action_id=task.action_id, expires_at=utcnow_naive()+timedelta(minutes=1), consumed_count=1, execution_limit=1),
    ]
    for authorization in cases:
        db = MagicMock()
        db.get = AsyncMock(side_effect=[task, authorization])
        assert await _claim_task(db, 2) is False


@pytest.mark.asyncio
async def test_concurrent_single_use_authorization_allows_at_most_one_claim():
    lock = asyncio.Lock()
    task = SimpleNamespace(id=3, target_id=7, status="pending", approval_status="not_required",
        tool_name="nuclei_safe", execution_authorization_id=5, action_id="nuclei.safe_scan.v1")
    authorization = SimpleNamespace(target_id=7, action_id=task.action_id,
        expires_at=utcnow_naive()+timedelta(minutes=1), consumed_count=0, execution_limit=1)

    async def claim_once():
        async with lock:  # models PostgreSQL row locks used by _claim_task
            if task.status != "pending" or authorization.consumed_count >= 1:
                return False
            authorization.consumed_count += 1
            task.status = "running"
            return True

    assert sum(await asyncio.gather(claim_once(), claim_once())) == 1
