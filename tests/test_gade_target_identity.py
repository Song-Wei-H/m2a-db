"""TID-01..08 target-identity controls; MOCK/Fake only, never a live target test."""
from datetime import UTC, datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import ValidationError
from starlette.testclient import TestClient

from app import action_contracts as contracts
from app.execution_governance import evaluate_and_authorize
from app.execution_trace import context_evidence, evidence_ref, execution_request
from app.models import Target
from app.security.llm_schema import LlmToolProposal
from app.target_identity import VerifiedTargetIdentity, target_identity_binding_for_grant


pytestmark = pytest.mark.skipif(not contracts.HOME_LAB_EXPLORATORY, reason="home-only identity policy")
ACTION = "lab.synthetic_node_discovery.v1"
TOOL = "lab_synthetic_node_discovery"
IDENTITY = "gade-l2-t1078"


@pytest.fixture(autouse=True)
def worker_replay_ledger(monkeypatch, tmp_path):
    monkeypatch.setenv("KALI_WORKER_REPLAY_DB_PATH", str(tmp_path / "worker-replay.sqlite3"))


def replay_worker_request(worker, target, result, *, task_id=1004):
    params = params_for(target)
    return {
        "tool": TOOL, "target": target.target, "port": 18080, "protocol": "tcp", "service": "http",
        "action_id": ACTION, "execution_identity": contracts.ACTION_IDENTITIES[ACTION],
        "authorization_parameters": params, "authorization_parameters_hash": worker.parameters_hash(params),
        "task_id": task_id, "authorization_id": result.authorization.id, "request_id": str(uuid4()),
        "correlation_id": "worker-replay-probe", "template_id": contracts.ACTION_TEMPLATES[ACTION],
        "expected_worker_build_sha256": worker.WORKER_BUILD_SHA256,
        "target_identity_binding": target_identity_binding_for_grant(result.evaluation, result.authorization),
    }


class FakeSession:
    def __init__(self, action_row):
        self.action_row = action_row
        self.added = []

    async def execute(self, _statement):
        return SimpleNamespace(scalar_one_or_none=lambda: self.action_row)

    def add(self, row):
        self.added.append(row)

    async def flush(self):
        for index, row in enumerate(self.added, 1):
            if getattr(row, "id", None) is None:
                row.id = index


class FakeVerifier:
    def __init__(self, *, identity=IDENTITY, fingerprint="a" * 64,
                 verified_at=None, expires_at=None, error=None,
                 verification_mode="MOCK", scope=None):
        self.identity = identity
        self.fingerprint = fingerprint
        self.verified_at = verified_at
        self.expires_at = expires_at
        self.error = error
        self.verification_mode = verification_mode
        self.scope = scope
        self.calls = 0

    def verify_target(self, *, target, expected_identity, port):
        self.calls += 1
        if self.error:
            raise RuntimeError("mock verifier unavailable")
        now = datetime.now(UTC)
        return VerifiedTargetIdentity(
            target_id=target.id, target_identity=self.identity, endpoint=target.target,
            port=port, scope=self.scope if self.scope is not None else target.scope,
            verifier_id="test.mock-target-registry.v1",
            identity_fingerprint=self.fingerprint, evidence_sha256="b" * 64,
            verified_at=self.verified_at or now,
            expires_at=self.expires_at or (now + timedelta(seconds=30)),
            verification_mode=self.verification_mode,
        )


def target_row():
    target = Target(id=73, target="127.0.0.1", target_type="ip", scope="127.0.0.1/32")
    target.authorization_depth = 6
    target.authorization_policy_version = "m2a-attack-depth-v1"
    target.authorization_configured_by = "operator-ui"
    target.authorization_effective_from = datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=1)
    target.authorization_expires_at = datetime.now(UTC).replace(tzinfo=None) + timedelta(minutes=5)
    return target


def action_row():
    return SimpleNamespace(action_id=ACTION, validation_tier=6, enabled=True,
        execution_identity=contracts.ACTION_IDENTITIES[ACTION],
        template_version=contracts.ACTION_TEMPLATES[ACTION])


def params_for(target):
    return contracts.canonical_action_parameters(action_id=ACTION, target=target.target,
        port=18080, protocol="tcp", service="http")


def refs_for(target):
    return context_evidence(target) + [evidence_ref(
        "decision_scores:tid-test", {"next_tool": TOOL, "next_action": "read fixed topology"}, "decision_input")]


async def allowed_mock_result(verifier=None, *, allow_mock=True):
    target = target_row()
    result = await evaluate_and_authorize(
        FakeSession(action_row()), target=target, tool_name=TOOL, parameters=params_for(target),
        reason="TID isolated verifier test", confidence=1.0, provider="test",
        authorization_source="test", ttl_seconds=30, evidence_refs=refs_for(target),
        _target_identity_verifier=verifier or FakeVerifier(), _allow_mock_target_identity=allow_mock,
    )
    return target, result


@pytest.mark.asyncio
async def test_tid_01_matching_mock_identity_allows_and_binds_identity_to_grant(monkeypatch):
    monkeypatch.setenv("GADE_HOME_AUTONOMOUS_POLICY_VERSION", "gade-home-autonomous-policy-v1")
    target, result = await allowed_mock_result()
    assert result.evaluation.outcome == "ALLOW"
    assert result.authorization is not None
    assert result.evaluation.contract_snapshot["target_identity_check"] == "PASS"
    assert result.evaluation.contract_snapshot["target_identity_binding"] == result.target_identity_binding
    assert result.target_identity_binding["authorization_id"] == result.authorization.id
    assert target_identity_binding_for_grant(result.evaluation, result.authorization) == result.target_identity_binding
    assert result.target_identity_binding["verification_mode"] == "MOCK"
    worker_request = execution_request(SimpleNamespace(
        tool_name=TOOL, host="127.0.0.1", port=18080, protocol="tcp", service="http",
        action_id=ACTION, execution_identity=contracts.ACTION_IDENTITIES[ACTION],
        authorization_parameters=params_for(target),
        authorization_parameters_hash=result.authorization.parameters_hash,
        task_id=88, authorization_id=result.authorization.id, request_id="tid-01",
        correlation_id="tid-01-correlation", template_id=contracts.ACTION_TEMPLATES[ACTION],
        expected_worker_build_sha256="d" * 64,
        authorization_decision=result.evaluation, execution_authorization=result.authorization,
    ))
    assert worker_request["target_identity_binding"] == result.target_identity_binding


@pytest.mark.asyncio
async def test_tid_02_identity_mismatch_denies_without_grant(monkeypatch):
    monkeypatch.setenv("GADE_HOME_AUTONOMOUS_POLICY_VERSION", "gade-home-autonomous-policy-v1")
    target = target_row()
    result = await evaluate_and_authorize(
        FakeSession(action_row()), target=target, tool_name=TOOL, parameters=params_for(target),
        reason="wrong identity", confidence=1.0, provider="test", authorization_source="test",
        ttl_seconds=30, evidence_refs=refs_for(target), _target_identity_verifier=FakeVerifier(identity="other-target"),
        _allow_mock_target_identity=True)
    assert result.evaluation.outcome == "DENY"
    assert result.evaluation.contract_snapshot["reason_code"] == "TARGET_IDENTITY_MISMATCH"
    assert result.authorization is None


@pytest.mark.asyncio
async def test_tid_03_missing_verifier_denies_without_grant(monkeypatch):
    monkeypatch.setenv("GADE_HOME_AUTONOMOUS_POLICY_VERSION", "gade-home-autonomous-policy-v1")
    target = target_row()
    result = await evaluate_and_authorize(
        FakeSession(action_row()), target=target, tool_name=TOOL, parameters=params_for(target),
        reason="no identity source", confidence=1.0, provider="test", authorization_source="test",
        ttl_seconds=30, evidence_refs=refs_for(target), _target_identity_verifier=None)
    assert result.evaluation.outcome == "DENY"
    assert result.evaluation.contract_snapshot["reason_code"] == "TARGET_IDENTITY_UNVERIFIED"
    assert result.evaluation.contract_snapshot["target_identity_check"] == "FAIL"
    assert result.authorization is None


def test_tid_04_proposal_cannot_self_declare_target_identity():
    with pytest.raises(ValidationError):
        LlmToolProposal.model_validate({
            "tool": TOOL, "target": "127.0.0.1", "reason": "fake identity claim",
            "risk_level": "info", "target_identity": IDENTITY,
        })


@pytest.mark.asyncio
async def test_tid_05_worker_runtime_denies_target_replacement_after_grant(monkeypatch):
    monkeypatch.setenv("GADE_HOME_AUTONOMOUS_POLICY_VERSION", "gade-home-autonomous-policy-v1")
    target, result = await allowed_mock_result(
        FakeVerifier(fingerprint="a" * 64, verification_mode="LIVE_VERIFIED"), allow_mock=False)
    import kali_worker.app as worker

    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", "127.0.0.1/32")
    monkeypatch.setenv("GADE_ADVANCED_SYNTHETIC_ENABLED", "1")
    monkeypatch.setattr(worker, "get_configured_target_identity_verifier", lambda: FakeVerifier(
        fingerprint="c" * 64, verification_mode="LIVE_VERIFIED"))
    calls = []
    monkeypatch.setattr(worker, "run_lab_advanced_synthetic",
                        lambda _req: calls.append("called") or {"status": "completed"})
    params = params_for(target)
    body = {
        "tool": TOOL, "target": target.target, "port": 18080, "protocol": "tcp", "service": "http",
        "action_id": ACTION, "execution_identity": contracts.ACTION_IDENTITIES[ACTION],
        "authorization_parameters": params, "authorization_parameters_hash": worker.parameters_hash(params),
        "task_id": 1000, "authorization_id": result.authorization.id, "request_id": str(uuid4()),
        "correlation_id": "tid-05-test-correlation", "template_id": contracts.ACTION_TEMPLATES[ACTION],
        "expected_worker_build_sha256": worker.WORKER_BUILD_SHA256,
        "target_identity_binding": target_identity_binding_for_grant(result.evaluation, result.authorization),
    }
    response = TestClient(worker.app).post("/execute", json=body)
    assert response.status_code == 200
    assert response.json()["status"] == "rejected"
    assert response.json()["reason"] == "TARGET_IDENTITY_CHANGED"
    assert calls == []


@pytest.mark.asyncio
async def test_tid_09_worker_denies_independent_registry_scope_change_after_grant(monkeypatch):
    monkeypatch.setenv("GADE_HOME_AUTONOMOUS_POLICY_VERSION", "gade-home-autonomous-policy-v1")
    target, result = await allowed_mock_result(
        FakeVerifier(fingerprint="a" * 64, verification_mode="LIVE_VERIFIED"), allow_mock=False)
    import kali_worker.app as worker

    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", "127.0.0.1/32")
    monkeypatch.setenv("GADE_ADVANCED_SYNTHETIC_ENABLED", "1")
    monkeypatch.setattr(worker, "get_configured_target_identity_verifier", lambda: FakeVerifier(
        fingerprint="a" * 64, verification_mode="LIVE_VERIFIED", scope="127.0.0.0/24"))
    calls = []
    monkeypatch.setattr(worker, "run_lab_advanced_synthetic",
                        lambda _req: calls.append("called") or {"status": "completed"})
    params = params_for(target)
    body = {
        "tool": TOOL, "target": target.target, "port": 18080, "protocol": "tcp", "service": "http",
        "action_id": ACTION, "execution_identity": contracts.ACTION_IDENTITIES[ACTION],
        "authorization_parameters": params, "authorization_parameters_hash": worker.parameters_hash(params),
        "task_id": 1002, "authorization_id": result.authorization.id, "request_id": str(uuid4()),
        "correlation_id": "tid-09-scope-change", "template_id": contracts.ACTION_TEMPLATES[ACTION],
        "expected_worker_build_sha256": worker.WORKER_BUILD_SHA256,
        "target_identity_binding": target_identity_binding_for_grant(result.evaluation, result.authorization),
    }
    response = TestClient(worker.app).post("/execute", json=body)
    assert response.status_code == 200
    assert response.json()["status"] == "rejected"
    assert response.json()["reason"] == "TARGET_IDENTITY_MISMATCH"
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(("change", "reason"), [
    ("target", "advanced synthetic action is fixed to the home Lab HTTP endpoint"),
    ("parameters", "authorization parameter identity mismatch"),
    ("action", "execution identity mismatch"),
])
async def test_tid_10_worker_denies_replaced_action_target_or_parameters(monkeypatch, change, reason):
    monkeypatch.setenv("GADE_HOME_AUTONOMOUS_POLICY_VERSION", "gade-home-autonomous-policy-v1")
    target, result = await allowed_mock_result(
        FakeVerifier(fingerprint="a" * 64, verification_mode="LIVE_VERIFIED"), allow_mock=False)
    import kali_worker.app as worker

    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", "127.0.0.1/32")
    monkeypatch.setenv("GADE_ADVANCED_SYNTHETIC_ENABLED", "1")
    monkeypatch.setattr(worker, "get_configured_target_identity_verifier", lambda: FakeVerifier(
        fingerprint="a" * 64, verification_mode="LIVE_VERIFIED"))
    calls = []
    monkeypatch.setattr(worker, "run_lab_advanced_synthetic",
                        lambda _req: calls.append("called") or {"status": "completed"})
    params = params_for(target)
    body = {
        "tool": TOOL, "target": target.target, "port": 18080, "protocol": "tcp", "service": "http",
        "action_id": ACTION, "execution_identity": contracts.ACTION_IDENTITIES[ACTION],
        "authorization_parameters": params, "authorization_parameters_hash": worker.parameters_hash(params),
        "task_id": 1003, "authorization_id": result.authorization.id, "request_id": str(uuid4()),
        "correlation_id": "tid-10-replacement", "template_id": contracts.ACTION_TEMPLATES[ACTION],
        "expected_worker_build_sha256": worker.WORKER_BUILD_SHA256,
        "target_identity_binding": target_identity_binding_for_grant(result.evaluation, result.authorization),
    }
    if change == "target":
        body["target"] = "127.0.0.2"
    elif change == "parameters":
        body["authorization_parameters"] = {**params, "target": "127.0.0.2"}
        body["authorization_parameters_hash"] = worker.parameters_hash(body["authorization_parameters"])
    else:
        body["action_id"] = "lab.synthetic_node_session.v1"

    response = TestClient(worker.app).post("/execute", json=body)
    assert response.status_code == 200
    assert response.json()["status"] == "rejected"
    assert response.json()["reason"] == reason
    assert calls == []


@pytest.mark.asyncio
async def test_worker_replay_rejects_exact_duplicate_before_second_handler(monkeypatch):
    """The handler is stubbed; this is an offline replay regression, not an Action run."""
    monkeypatch.setenv("GADE_HOME_AUTONOMOUS_POLICY_VERSION", "gade-home-autonomous-policy-v1")
    target, result = await allowed_mock_result(
        FakeVerifier(fingerprint="a" * 64, verification_mode="LIVE_VERIFIED"), allow_mock=False)
    import kali_worker.app as worker

    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", "127.0.0.1/32")
    monkeypatch.setenv("GADE_ADVANCED_SYNTHETIC_ENABLED", "1")
    monkeypatch.setattr(worker, "get_configured_target_identity_verifier", lambda: FakeVerifier(
        fingerprint="a" * 64, verification_mode="LIVE_VERIFIED"))
    calls = []
    monkeypatch.setattr(worker, "run_lab_advanced_synthetic",
                        lambda _req: calls.append("stub") or {"status": "completed"})
    body = replay_worker_request(worker, target, result)
    client = TestClient(worker.app)

    first = client.post("/execute", json=body)
    replay = client.post("/execute", json=body)

    assert first.status_code == 200 and replay.status_code == 200
    assert first.json()["status"] == "completed"
    assert replay.json()["status"] == "rejected"
    assert replay.json()["reason"] == "AUTHORIZATION_ALREADY_CLAIMED"
    assert first.json()["execution_receipt"]["handler_invoked"] is True
    assert first.json()["execution_receipt"]["worker_replay_claim"] == "PERSISTED_SINGLE_USE"
    assert "execution_receipt" not in replay.json()
    assert calls == ["stub"]


@pytest.mark.asyncio
async def test_worker_replay_rejects_mutated_request_envelope(monkeypatch):
    monkeypatch.setenv("GADE_HOME_AUTONOMOUS_POLICY_VERSION", "gade-home-autonomous-policy-v1")
    target, result = await allowed_mock_result(
        FakeVerifier(fingerprint="a" * 64, verification_mode="LIVE_VERIFIED"), allow_mock=False)
    import kali_worker.app as worker

    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", "127.0.0.1/32")
    monkeypatch.setenv("GADE_ADVANCED_SYNTHETIC_ENABLED", "1")
    monkeypatch.setattr(worker, "get_configured_target_identity_verifier", lambda: FakeVerifier(
        fingerprint="a" * 64, verification_mode="LIVE_VERIFIED"))
    calls = []
    monkeypatch.setattr(worker, "run_lab_advanced_synthetic",
                        lambda _req: calls.append("stub") or {"status": "completed"})
    body = replay_worker_request(worker, target, result, task_id=1007)
    client = TestClient(worker.app)

    first = client.post("/execute", json=body)
    mutated = {**body, "correlation_id": "changed-correlation-envelope"}
    replay = client.post("/execute", json=mutated)

    assert first.json()["status"] == "completed"
    assert replay.json()["status"] == "rejected"
    assert replay.json()["reason"] == "AUTHORIZATION_REPLAY_CONFLICT"
    assert calls == ["stub"]


@pytest.mark.asyncio
async def test_worker_concurrent_duplicate_requests_invoke_stub_handler_once(monkeypatch):
    monkeypatch.setenv("GADE_HOME_AUTONOMOUS_POLICY_VERSION", "gade-home-autonomous-policy-v1")
    target, result = await allowed_mock_result(
        FakeVerifier(fingerprint="a" * 64, verification_mode="LIVE_VERIFIED"), allow_mock=False)
    import kali_worker.app as worker

    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", "127.0.0.1/32")
    monkeypatch.setenv("GADE_ADVANCED_SYNTHETIC_ENABLED", "1")
    monkeypatch.setattr(worker, "get_configured_target_identity_verifier", lambda: FakeVerifier(
        fingerprint="a" * 64, verification_mode="LIVE_VERIFIED"))
    calls = []
    monkeypatch.setattr(worker, "run_lab_advanced_synthetic",
                        lambda _req: calls.append("stub") or {"status": "completed"})
    body = replay_worker_request(worker, target, result, task_id=1005)
    start = Barrier(2)

    def post_once():
        start.wait(timeout=5)
        with TestClient(worker.app) as client:
            return client.post("/execute", json=body).json()

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _index: post_once(), range(2)))

    assert sorted(item["status"] for item in responses) == ["completed", "rejected"]
    assert sum(item.get("reason") == "AUTHORIZATION_ALREADY_CLAIMED" for item in responses) == 1
    assert calls == ["stub"]


@pytest.mark.asyncio
async def test_worker_replay_ledger_unavailable_fails_closed_before_handler(monkeypatch):
    monkeypatch.setenv("GADE_HOME_AUTONOMOUS_POLICY_VERSION", "gade-home-autonomous-policy-v1")
    target, result = await allowed_mock_result(
        FakeVerifier(fingerprint="a" * 64, verification_mode="LIVE_VERIFIED"), allow_mock=False)
    import kali_worker.app as worker

    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", "127.0.0.1/32")
    monkeypatch.setenv("GADE_ADVANCED_SYNTHETIC_ENABLED", "1")
    monkeypatch.setattr(worker, "get_configured_target_identity_verifier", lambda: FakeVerifier(
        fingerprint="a" * 64, verification_mode="LIVE_VERIFIED"))
    monkeypatch.delenv("KALI_WORKER_REPLAY_DB_PATH", raising=False)
    calls = []
    monkeypatch.setattr(worker, "run_lab_advanced_synthetic",
                        lambda _req: calls.append("stub") or {"status": "completed"})
    response = TestClient(worker.app).post(
        "/execute", json=replay_worker_request(worker, target, result, task_id=1006))

    assert response.json()["status"] == "rejected"
    assert response.json()["reason"] == "REPLAY_LEDGER_UNAVAILABLE"
    assert calls == []


@pytest.mark.asyncio
async def test_tid_06_expired_identity_evidence_denies_without_grant(monkeypatch):
    monkeypatch.setenv("GADE_HOME_AUTONOMOUS_POLICY_VERSION", "gade-home-autonomous-policy-v1")
    now = datetime.now(UTC)
    target = target_row()
    result = await evaluate_and_authorize(
        FakeSession(action_row()), target=target, tool_name=TOOL, parameters=params_for(target),
        reason="expired proof", confidence=1.0, provider="test", authorization_source="test",
        ttl_seconds=30, evidence_refs=refs_for(target),
        _target_identity_verifier=FakeVerifier(verified_at=now - timedelta(seconds=90),
                                               expires_at=now - timedelta(seconds=1)),
        _allow_mock_target_identity=True)
    assert result.evaluation.outcome == "DENY"
    assert result.evaluation.contract_snapshot["reason_code"] == "TARGET_IDENTITY_EVIDENCE_EXPIRED"
    assert result.authorization is None


@pytest.mark.asyncio
async def test_tid_07_verifier_failure_denies_without_grant(monkeypatch):
    monkeypatch.setenv("GADE_HOME_AUTONOMOUS_POLICY_VERSION", "gade-home-autonomous-policy-v1")
    target = target_row()
    result = await evaluate_and_authorize(
        FakeSession(action_row()), target=target, tool_name=TOOL, parameters=params_for(target),
        reason="verifier unavailable", confidence=1.0, provider="test", authorization_source="test",
        ttl_seconds=30, evidence_refs=refs_for(target),
        _target_identity_verifier=FakeVerifier(error=True), _allow_mock_target_identity=True)
    assert result.evaluation.outcome == "DENY"
    assert result.evaluation.contract_snapshot["reason_code"] == "TARGET_IDENTITY_VERIFIER_UNAVAILABLE"
    assert result.authorization is None


@pytest.mark.asyncio
async def test_tid_08_worker_rejects_without_invoking_action_when_no_live_verifier(monkeypatch):
    monkeypatch.setenv("GADE_HOME_AUTONOMOUS_POLICY_VERSION", "gade-home-autonomous-policy-v1")
    target, result = await allowed_mock_result()
    assert result.authorization is not None
    binding = target_identity_binding_for_grant(result.evaluation, result.authorization)
    assert binding is not None

    import kali_worker.app as worker

    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", "127.0.0.1/32")
    monkeypatch.setenv("GADE_ADVANCED_SYNTHETIC_ENABLED", "1")
    calls = []
    monkeypatch.setattr(worker, "run_lab_advanced_synthetic", lambda _req: calls.append("called") or {"status": "completed"})
    params = params_for(target)
    body = {
        "tool": TOOL, "target": target.target, "port": 18080, "protocol": "tcp", "service": "http",
        "action_id": ACTION, "execution_identity": contracts.ACTION_IDENTITIES[ACTION],
        "authorization_parameters": params, "authorization_parameters_hash": worker.parameters_hash(params),
        "task_id": 1001, "authorization_id": result.authorization.id, "request_id": str(uuid4()),
        "correlation_id": "tid-08-test-correlation", "template_id": contracts.ACTION_TEMPLATES[ACTION],
        "expected_worker_build_sha256": worker.WORKER_BUILD_SHA256,
        "target_identity_binding": binding,
    }
    response = TestClient(worker.app).post("/execute", json=body)
    assert response.status_code == 200
    assert response.json()["status"] == "rejected"
    assert response.json()["reason"] == "TARGET_IDENTITY_UNVERIFIED"
    assert calls == []
