from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.action_contracts import ACTION_BY_TOOL, ACTION_IDENTITIES, ACTION_REQUIRED_ATTACK_DEPTH, ACTION_TEMPLATES, HOME_LAB_EXPLORATORY, HOME_ADVANCED_ACTIONS, canonical_action_parameters
from app.attack_authorization import ATTACK_AUTHORIZATION_LEVELS, depth_decision, level_definitions
from app.api.targets import update_target_authorization
from app.execution_governance import evaluate_and_authorize
from app.execution_trace import context_evidence
from app.main import app
from app.models import Target
from app.schemas import AttackAuthorizationDepthUpdate, TargetCreate
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock


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


def make_target(depth=1):
    target = Target(id=17, target="198.51.100.17", target_type="ip", scope="internal")
    target.authorization_depth = depth
    return target


def make_action(action_id="nuclei.safe_scan.v1"):
    return SimpleNamespace(
        action_id=action_id,
        validation_tier=1,
        execution_identity=ACTION_IDENTITIES[action_id],
        template_version=ACTION_TEMPLATES[action_id],
    )


def make_parameters(target, action_id="nuclei.safe_scan.v1", host=None):
    return canonical_action_parameters(
        action_id=action_id,
        target=host or target.target,
        port=443,
        protocol="tcp",
        service="https",
    )


def test_exactly_seven_cumulative_levels_and_attck_tactics_are_defined():
    definitions = level_definitions()
    assert len(definitions) == 7
    assert [item["cumulative"] for item in definitions] == [list(range(1, n + 1)) for n in range(1, 8)]
    assert ATTACK_AUTHORIZATION_LEVELS[7]["tactics"] == [
        "Collection", "Command and Control", "Exfiltration", "Impact",
    ]
    assert "not official linear" in "M2A cumulative authorization depth; not official linear MITRE ATT&CK phases."
    assert set(ACTION_REQUIRED_ATTACK_DEPTH) == set(ACTION_BY_TOOL.values())
    assert set(ACTION_REQUIRED_ATTACK_DEPTH.values()) == ({1, 2, 3, 4, 5, 6, 7} if HOME_LAB_EXPLORATORY else {1, 2, 3, 4})


def test_level_definitions_api_is_backend_authoritative():
    response = TestClient(app).get("/authorization/attack-levels")
    assert response.status_code == 200
    body = response.json()
    assert len(body["levels"]) == 7
    assert body["levels"][0]["registered_actions"]
    assert body["levels"][1]["registered_actions"] == ["lab_valid_account_access"]
    assert body["levels"][2]["registered_actions"] == ["lab_fixed_python_execution"]
    assert body["levels"][3]["registered_actions"] == ["lab_synthetic_role_lease"]
    if HOME_LAB_EXPLORATORY:
        for depth in (5, 6, 7):
            assert set(body["levels"][depth - 1]["registered_actions"]) == {
                tool for tool, (_, registered_depth, _) in HOME_ADVANCED_ACTIONS.items()
                if registered_depth == depth
            }
    else:
        assert all(not item["registered_actions"] for item in body["levels"][4:])


@pytest.mark.parametrize(
    ("authorized", "required", "passed", "reason"),
    [
        (1, 1, True, None),
        (1, 2, False, "ATTACK_DEPTH_EXCEEDED"),
        (3, 2, True, None),
        (3, 4, False, "ATTACK_DEPTH_EXCEEDED"),
        (7, 7, True, None),
    ],
)
def test_cumulative_depth_decision(authorized, required, passed, reason):
    result = depth_decision(authorized, required)
    assert result["passed"] is passed
    assert result["reason_code"] == reason


@pytest.mark.asyncio
async def test_missing_evidence_is_pending_and_creates_no_execution_authorization(monkeypatch):
    import app.action_contracts as contracts

    action_id = ACTION_BY_TOOL["nuclei_safe"]
    monkeypatch.setitem(contracts.ACTION_REQUIRED_ATTACK_DEPTH, action_id, 7)
    target = make_target(7)
    db = GovernanceSession(make_action(action_id))
    result = await evaluate_and_authorize(
        db,
        target=target,
        tool_name="nuclei_safe",
        parameters=make_parameters(target),
        reason="test missing evidence",
        confidence=0.5,
        provider="test",
        authorization_source="test",
        evidence_refs=[],
    )
    assert result.authorization is None
    assert result.proposal.status == "pending_evidence"
    assert result.evaluation.outcome == "PENDING"
    assert result.evaluation.contract_snapshot["reason_code"] == "EVIDENCE_REQUIRED"
    assert not any(row.__class__.__name__ == "ExecutionAuthorization" for row in db.added)


@pytest.mark.asyncio
async def test_depth_pass_continues_through_evidence_gate_to_authorization(monkeypatch):
    import app.action_contracts as contracts

    action_id = ACTION_BY_TOOL["nuclei_safe"]
    monkeypatch.setitem(contracts.ACTION_REQUIRED_ATTACK_DEPTH, action_id, 2)
    target = make_target(3)
    db = GovernanceSession(make_action(action_id))
    result = await evaluate_and_authorize(
        db, target=target, tool_name="nuclei_safe", parameters=make_parameters(target),
        reason="depth is sufficient", confidence=0.5, provider="test",
        authorization_source="test", evidence_refs=context_evidence(target),
    )
    assert result.authorization is not None
    assert result.evaluation.outcome == "ALLOW"
    assert result.evaluation.contract_snapshot["depth_check"] == "PASS"
    assert result.evaluation.contract_snapshot["evidence_check"] == "PASS"


@pytest.mark.asyncio
async def test_level_seven_does_not_authorize_out_of_target_parameters():
    target = make_target(7)
    db = GovernanceSession(make_action())
    result = await evaluate_and_authorize(
        db, target=target, tool_name="nuclei_safe",
        parameters=make_parameters(target, host="198.51.100.99"),
        reason="target drift", confidence=0.5, provider="test",
        authorization_source="test", evidence_refs=context_evidence(target),
    )
    assert result.authorization is None
    assert result.evaluation.outcome == "DENY"
    assert result.evaluation.contract_snapshot["scope_check"] == "FAIL"


@pytest.mark.asyncio
async def test_backend_registry_requirement_overrides_llm_tactic_and_depth_claim(monkeypatch):
    action_id = ACTION_BY_TOOL["nuclei_safe"]
    monkeypatch.setitem(__import__("app.action_contracts", fromlist=["ACTION_REQUIRED_ATTACK_DEPTH"]).ACTION_REQUIRED_ATTACK_DEPTH,
                        action_id, 4)
    target = make_target(3)
    db = GovernanceSession(make_action(action_id))
    result = await evaluate_and_authorize(
        db, target=target, tool_name="nuclei_safe", parameters=make_parameters(target),
        reason="LLM says Reconnaissance requires depth 1", confidence=0.5,
        provider="llm", authorization_source="test",
        evidence_refs=context_evidence(target),
        raw_proposal={"tactic": "Reconnaissance", "required_depth": 1},
    )
    assert result.authorization is None
    assert result.evaluation.reason == "超出本次授權深度 (ATTACK_DEPTH_EXCEEDED)"
    assert result.evaluation.contract_snapshot["required_depth"] == 4
    assert result.evaluation.contract_snapshot["depth_check"] == "FAIL"


@pytest.mark.asyncio
async def test_llm_cannot_lower_registry_required_depth(monkeypatch):
    import app.action_contracts as contracts

    action_id = ACTION_BY_TOOL["nuclei_safe"]
    monkeypatch.setitem(contracts.ACTION_REQUIRED_ATTACK_DEPTH, action_id, 5)
    target = make_target(4)
    db = GovernanceSession(make_action(action_id))
    result = await evaluate_and_authorize(
        db, target=target, tool_name="nuclei_safe", parameters=make_parameters(target),
        reason="LLM claims requirement 1", confidence=0.5, provider="llm",
        authorization_source="test", evidence_refs=context_evidence(target),
        raw_proposal={"required_depth": 1},
    )
    assert result.authorization is None
    assert result.evaluation.contract_snapshot["required_depth"] == 5
    assert result.evaluation.contract_snapshot["reason_code"] == "ATTACK_DEPTH_EXCEEDED"


def test_create_and_update_api_schemas_reject_out_of_range_depth():
    with pytest.raises(ValidationError):
        TargetCreate(target="198.51.100.17", authorization_depth=0)
    with pytest.raises(ValidationError):
        AttackAuthorizationDepthUpdate(authorization_depth=8)


@pytest.mark.asyncio
async def test_operator_update_persists_selected_depth_on_target_profile():
    target = make_target(1)
    target.authorization_policy_version = "legacy-safe-default"
    target.authorization_effective_from = None
    target.authorization_expires_at = None
    target.authorization_configured_by = "legacy-record"
    db = MagicMock()
    db.get = AsyncMock(return_value=target)
    db.commit = AsyncMock()

    profile = await update_target_authorization(
        17, AttackAuthorizationDepthUpdate(authorization_depth=2), db
    )
    assert target.authorization_depth == 2
    assert target.authorization_policy_version == "m2a-attack-depth-v1"
    assert target.authorization_configured_by == "operator-ui"
    assert profile.authorization_depth == 2
    db.commit.assert_awaited_once()
