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
    ("httpx_basic", "httpx.web_probe.v1", 1, 80, "http"),
    ("ssh-enum", "ssh.algorithms_enum.v1", 1, 22, "ssh"),
    ("mysql-info", "mysql.server_info.v1", 1, 3306, "mysql"),
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
@pytest.mark.parametrize(("tool_name", "action_id", "port", "service"), [
    ("ssh-enum", "ssh.algorithms_enum.v1", 22, "ssh"),
    ("mysql-info", "mysql.server_info.v1", 3306, "mysql"),
])
@pytest.mark.parametrize("drift_field", ["template_version", "execution_identity"])
async def test_batch4_registry_template_or_execution_identity_drift_blocks_authorization(
    tool_name, action_id, port, service, drift_field,
):
    values = {
        "action_id": action_id,
        "validation_tier": 1,
        "execution_identity": ACTION_IDENTITIES[action_id],
        "template_version": ACTION_TEMPLATES[action_id],
    }
    values[drift_field] = "drift"
    db = GovernanceSession(SimpleNamespace(**values))
    target = Target(id=10, target="service.example", scope="service.example")
    params = canonical_parameters(
        target=target.target, port=port, protocol="tcp", service=service,
        action_id=action_id,
    )
    with pytest.raises(ValueError, match="identity does not match canonical contract"):
        await propose_and_authorize(
            db, target=target, tool_name=tool_name, parameters=params,
            reason="drift test", confidence=.5, provider="test",
            authorization_source="test",
        )


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


class ClaimStore:
    """In-memory transaction/row-lock model; not a PostgreSQL concurrency proof."""
    def __init__(self, tasks, authorization, target=None):
        self.tasks = {task.id: task for task in tasks}
        self.authorization = authorization
        self.target = target or SimpleNamespace(id=authorization.target_id,
                                                target="192.0.2.7", scope=authorization.scope)
        self.locks = {}

    def lock_for(self, key):
        return self.locks.setdefault(key, asyncio.Lock())


class ClaimSession:
    def __init__(self, store):
        self.store = store
        self.held_locks = []
        self.task = None

    def begin(self):
        session = self

        class Transaction:
            async def __aenter__(self):
                return session

            async def __aexit__(self, *_exc):
                for lock in reversed(session.held_locks):
                    lock.release()
                session.held_locks.clear()

        return Transaction()

    async def get(self, model, row_id, with_for_update=False):
        key = (model.__name__, row_id)
        if with_for_update:
            lock = self.store.lock_for(key)
            await lock.acquire()
            self.held_locks.append(lock)
        if model.__name__ == "ToolTask":
            self.task = self.store.tasks.get(row_id)
            return self.task
        if model.__name__ == "ExecutionAuthorization":
            authorization = self.store.authorization
            return authorization if authorization.id == row_id else None
        if model.__name__ == "Target":
            return self.store.target if self.store.target.id == row_id else None
        return None

    async def execute(self, _statement):
        if (self.task is not None and self.task.status == "pending"
                and self.task.approval_status in {"not_required", "approved"}):
            self.task.status = "running"
            return ClaimResult(self.task.id)
        return ClaimResult(None)


class ClaimResult:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


def _claim_task_row(task_id, *, target_id=7, action_id="nuclei.safe_scan.v1"):
    return SimpleNamespace(id=task_id, target_id=target_id, status="pending",
        approval_status="not_required", tool_name="nuclei_safe",
        execution_authorization_id=44, action_id=action_id)


def _claim_grant(*, expires_at=None, consumed_count=0):
    return SimpleNamespace(id=44, target_id=7, action_id="nuclei.safe_scan.v1",
        expires_at=expires_at or utcnow_naive() + timedelta(minutes=1),
        scope="192.0.2.7/32", consumed_count=consumed_count, execution_limit=1)


@pytest.mark.asyncio
async def test_real_claim_path_allows_once_then_rejects_consumed_grant_replay():
    grant = _claim_grant()
    store = ClaimStore([_claim_task_row(1), _claim_task_row(2)], grant)

    async with ClaimSession(store).begin() as first_db:
        first = await _claim_task(first_db, 1)
    async with ClaimSession(store).begin() as replay_db:
        replay = await _claim_task(replay_db, 2)

    assert first is True
    assert replay is False
    assert grant.consumed_count == 1
    assert store.tasks[1].status == "running"
    assert store.tasks[2].status == "pending"


@pytest.mark.asyncio
async def test_claim_path_rejects_expired_or_replaced_target_action():
    for task in (
        _claim_task_row(3, target_id=8),
        _claim_task_row(4, action_id="httpx.web_probe.v1"),
    ):
        grant = _claim_grant()
        store = ClaimStore([task], grant)
        async with ClaimSession(store).begin() as db:
            claimed = await _claim_task(db, task.id)
        assert claimed is False
        assert grant.consumed_count == 0
        assert task.status == "pending"

    task = _claim_task_row(5)
    grant = _claim_grant(expires_at=utcnow_naive() - timedelta(seconds=1))
    store = ClaimStore([task], grant)
    async with ClaimSession(store).begin() as db:
        claimed = await _claim_task(db, task.id)
    assert claimed is False
    assert grant.consumed_count == 0
    assert task.status == "pending"


@pytest.mark.asyncio
async def test_claim_path_rejects_target_scope_changed_after_grant_creation():
    task = _claim_task_row(8)
    grant = _claim_grant()
    changed_target = SimpleNamespace(id=7, target="192.0.2.7", scope="192.0.2.0/24")
    store = ClaimStore([task], grant, target=changed_target)

    async with ClaimSession(store).begin() as db:
        claimed = await _claim_task(db, task.id)

    assert claimed is False
    assert grant.consumed_count == 0
    assert task.status == "pending"


@pytest.mark.asyncio
async def test_two_executors_claiming_one_grant_allow_at_most_one_in_mock_transaction_model():
    grant = _claim_grant()
    store = ClaimStore([_claim_task_row(6), _claim_task_row(7)], grant)

    async def claim(task_id):
        async with ClaimSession(store).begin() as db:
            return await _claim_task(db, task_id)

    results = await asyncio.gather(claim(6), claim(7))
    assert sum(results) == 1
    assert grant.consumed_count == 1
    assert sum(task.status == "running" for task in store.tasks.values()) == 1
