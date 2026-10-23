import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import action_contracts as contracts
from app.execution_governance import AuthorizationPolicyError, evaluate_and_authorize, propose_and_authorize
from app.execution_trace import context_evidence, evidence_ref
from app.models import Target
from app.target_identity import VerifiedTargetIdentity


class FakeSession:
    def __init__(self, action):
        self.action = action
        self.added = []

    async def execute(self, _statement):
        return SimpleNamespace(scalar_one_or_none=lambda: self.action)

    def add(self, row):
        self.added.append(row)

    async def flush(self):
        for index, row in enumerate(self.added, 1):
            if getattr(row, "id", None) is None:
                row.id = index


class FakeTargetIdentityVerifier:
    def __init__(self, *, identity="gade-l2-t1078", fingerprint="a" * 64, proof_sha="b" * 64):
        self.identity = identity
        self.fingerprint = fingerprint
        self.proof_sha = proof_sha

    def verify_target(self, *, target, expected_identity, port):
        now = datetime.now(UTC)
        return VerifiedTargetIdentity(
            target_id=target.id, target_identity=self.identity, endpoint=target.target, port=port,
            scope=target.scope, verifier_id="test.fake-target-registry.v1",
            identity_fingerprint=self.fingerprint, evidence_sha256=self.proof_sha,
            verified_at=now, expires_at=now + timedelta(seconds=30), verification_mode="MOCK",
        )


def _target(depth=6):
    target = Target(id=7, target="127.0.0.1", target_type="ip", scope="127.0.0.1/32")
    target.authorization_depth = depth
    target.authorization_policy_version = "m2a-attack-depth-v1"
    target.authorization_configured_by = "operator-ui"
    target.authorization_effective_from = datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=1)
    target.authorization_expires_at = datetime.now(UTC).replace(tzinfo=None) + timedelta(minutes=30)
    return target


def _evidence(target, tool):
    return context_evidence(target) + [evidence_ref(
        "decision_scores:42", {"next_tool": tool, "next_action": "enumerate fixed synthetic topology"},
        "decision_input")]


def test_policy_manifest_allows_only_reviewed_read_only_discovery():
    path = Path(__file__).resolve().parents[1] / "home-lab" / "action-contracts" / "autonomous-policy-v1.json"
    policy = json.loads(path.read_text(encoding="utf-8"))
    assert policy["policy_id"] == "gade-home-autonomous-policy-v1"
    assert policy["status"] == "CANDIDATE_DISABLED_BY_DEFAULT"
    allowed = [action for action, item in policy["actions"].items() if item["decision"] == "ALLOW"]
    assert allowed == ["lab.synthetic_node_discovery.v1"]
    assert len([item for item in policy["actions"].values() if item["decision"] == "DENY"]) == 8
    contract = json.loads((path.parent / "advanced-synthetic-v1.json").read_text(encoding="utf-8"))
    for item in contract["actions"]:
        entry = policy["actions"][item["action_id"]]
        assert entry["tool"] == item["tool"]
        assert entry["depth"] == item["depth"]
        assert entry["effect"] == item["effect"]
        assert entry["decision"] == ("ALLOW" if item["action_id"] == "lab.synthetic_node_discovery.v1" else "DENY")
    l4 = json.loads((path.parent / "l4-synthetic-role-lease-v1.json").read_text(encoding="utf-8"))
    assert policy["actions"][l4["action_id"]]["decision"] == "DENY"
    assert policy["actions"][l4["action_id"]]["depth"] == l4["required_depth"]


@pytest.mark.asyncio
async def test_autonomous_policy_allows_exact_l6_discovery_and_creates_bounded_grant(monkeypatch):
    monkeypatch.setenv("GADE_HOME_AUTONOMOUS_POLICY_VERSION", "gade-home-autonomous-policy-v1")
    tool = "lab_synthetic_node_discovery"
    action_id, depth, _ = contracts.HOME_ADVANCED_ACTIONS[tool]
    action = SimpleNamespace(action_id=action_id, validation_tier=depth, enabled=True,
        execution_identity=contracts.ACTION_IDENTITIES[action_id],
        template_version=contracts.ACTION_TEMPLATES[action_id])
    target = _target()
    params = contracts.canonical_action_parameters(action_id=action_id,
        target=target.target, port=18080, protocol="tcp", service="http")
    db = FakeSession(action)
    result = await evaluate_and_authorize(db, target=target, tool_name=tool,
        parameters=params, reason="read fixed synthetic topology", confidence=1.0,
        provider="test", authorization_source="test", ttl_seconds=30,
        evidence_refs=_evidence(target, tool), _target_identity_verifier=FakeTargetIdentityVerifier(),
        _allow_mock_target_identity=True)
    assert result.evaluation.outcome == "ALLOW", result.evaluation.contract_snapshot
    assert result.evaluation.contract_snapshot["authorization_basis"] == "autonomous-policy:gade-home-autonomous-policy-v1"
    assert result.authorization.execution_limit == 1
    assert result.authorization.human_approved_by is None
    assert result.authorization.authorization_source == "autonomous-policy:gade-home-autonomous-policy-v1"
    assert result.target_identity_binding["authorization_id"] == result.authorization.id
    assert result.evaluation.contract_snapshot["target_identity_binding"] == result.target_identity_binding


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["disabled", "missing_evidence", "tampered_evidence", "wrong_depth", "wrong_scope", "expired_profile", "long_ttl"])
async def test_autonomous_policy_denies_invalid_context_without_grant(monkeypatch, case):
    if case != "disabled":
        monkeypatch.setenv("GADE_HOME_AUTONOMOUS_POLICY_VERSION", "gade-home-autonomous-policy-v1")
    else:
        monkeypatch.delenv("GADE_HOME_AUTONOMOUS_POLICY_VERSION", raising=False)
    tool = "lab_synthetic_node_discovery"
    action_id, depth, _ = contracts.HOME_ADVANCED_ACTIONS[tool]
    action = SimpleNamespace(action_id=action_id, validation_tier=depth, enabled=True,
        execution_identity=contracts.ACTION_IDENTITIES[action_id],
        template_version=contracts.ACTION_TEMPLATES[action_id])
    target = _target(depth=5 if case == "wrong_depth" else 6)
    if case == "wrong_scope":
        target.scope = "127.0.0.0/24"
    if case == "expired_profile":
        target.authorization_expires_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=1)
    params = contracts.canonical_action_parameters(action_id=action_id,
        target=target.target, port=18080, protocol="tcp", service="http")
    evidence = [] if case == "missing_evidence" else _evidence(target, tool)
    if case == "tampered_evidence":
        evidence[0]["content"]["scope"] = "127.0.0.0/24"
    ttl = 61 if case == "long_ttl" else 30
    db = FakeSession(action)
    result = await evaluate_and_authorize(db, target=target, tool_name=tool,
        parameters=params, reason="negative policy case", confidence=1.0,
        provider="test", authorization_source="test", ttl_seconds=ttl,
        evidence_refs=evidence, _target_identity_verifier=FakeTargetIdentityVerifier(),
        _allow_mock_target_identity=True)
    assert result.evaluation.outcome == "DENY"
    assert result.authorization is None
    assert result.evaluation.authorization_id is None


@pytest.mark.asyncio
async def test_unreviewed_advanced_action_is_denied_even_with_policy_enabled(monkeypatch):
    monkeypatch.setenv("GADE_HOME_AUTONOMOUS_POLICY_VERSION", "gade-home-autonomous-policy-v1")
    tool = "lab_synthetic_node_session"
    action_id, depth, _ = contracts.HOME_ADVANCED_ACTIONS[tool]
    action = SimpleNamespace(action_id=action_id, validation_tier=depth, enabled=True,
        execution_identity=contracts.ACTION_IDENTITIES[action_id],
        template_version=contracts.ACTION_TEMPLATES[action_id])
    target = _target(depth=7)
    params = contracts.canonical_action_parameters(action_id=action_id,
        target=target.target, port=18080, protocol="tcp", service="http")
    db = FakeSession(action)
    result = await evaluate_and_authorize(db, target=target, tool_name=tool,
        parameters=params, reason="unreviewed action", confidence=1.0,
        provider="test", authorization_source="test", ttl_seconds=30,
        evidence_refs=_evidence(target, tool), _target_identity_verifier=FakeTargetIdentityVerifier(),
        _allow_mock_target_identity=True)
    assert result.evaluation.outcome == "DENY"
    assert result.authorization is None
    assert result.evaluation.contract_snapshot["reason_code"] == "AUTONOMOUS_ACTION_NOT_ALLOWLISTED"


@pytest.mark.asyncio
async def test_direct_legacy_authorization_path_cannot_bypass_autonomous_policy(monkeypatch):
    monkeypatch.setenv("GADE_HOME_AUTONOMOUS_POLICY_VERSION", "gade-home-autonomous-policy-v1")
    tool = "lab_synthetic_node_discovery"
    action_id, depth, _ = contracts.HOME_ADVANCED_ACTIONS[tool]
    action = SimpleNamespace(action_id=action_id, validation_tier=depth, enabled=True,
        execution_identity=contracts.ACTION_IDENTITIES[action_id],
        template_version=contracts.ACTION_TEMPLATES[action_id])
    target = _target()
    params = contracts.canonical_action_parameters(action_id=action_id,
        target=target.target, port=18080, protocol="tcp", service="http")
    db = FakeSession(action)
    with pytest.raises(AuthorizationPolicyError, match="Autonomous action policy denied"):
        await propose_and_authorize(db, target=target, tool_name=tool, parameters=params,
            reason="direct-call negative case", confidence=1.0, provider="test",
            authorization_source="test", human_approved_by="legacy-approval",
            _target_identity_verifier=FakeTargetIdentityVerifier(), _allow_mock_target_identity=True,
            ttl_seconds=30)
    assert not any(type(row).__name__ in {"ExecutionAuthorization", "ToolTask"} for row in db.added)
