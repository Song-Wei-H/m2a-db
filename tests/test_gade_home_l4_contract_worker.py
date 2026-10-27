import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


def _modules(monkeypatch):
    monkeypatch.setenv("GADE_HOME_LAB_EXPLORATORY", "1")
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", "127.0.0.1/32")
    import app.action_contracts as contracts
    import kali_worker.app as worker
    monkeypatch.setattr(contracts, "HOME_LAB_EXPLORATORY", True)
    monkeypatch.setattr(worker, "HOME_LAB_EXPLORATORY", True)
    return contracts, worker


def test_l4_contract_is_fixed_home_only_and_disabled_by_default(monkeypatch):
    contracts, worker = _modules(monkeypatch)
    assert contracts.ACTION_REQUIRED_ATTACK_DEPTH["lab.synthetic_role_lease.v1"] == 4
    assert "lab_synthetic_role_lease" not in worker.effective_allowed_tools()
    params = contracts.canonical_action_parameters(
        action_id="lab.synthetic_role_lease.v1", target="127.0.0.1", port=18080,
        protocol="tcp", service="http")
    assert params["lease_path"] == "/lab/l4/role-lease"
    with pytest.raises(ValueError):
        contracts.canonical_action_parameters(
            action_id="lab.synthetic_role_lease.v1", target="10.56.66.119", port=18080,
            protocol="tcp", service="http")
    monkeypatch.setenv("GADE_L4_SYNTHETIC_ENABLED", "1")
    assert "lab_synthetic_role_lease" in worker.effective_allowed_tools()


def test_l4_normalizer_is_bounded_and_does_not_project_secrets():
    from worker.evidence_normalizer import normalize_tool_result

    parsed = {"success": True, "status": "done", "test_case_id": "GADE-L4-ENGINEERING-abcdef123456",
              "lease_http_status": 200, "protected_http_status": 200,
              "role": "synthetic-lab-operator", "lease_ttl_seconds": 300,
              "simulation": True, "state_sha256": "a" * 64,
              "session_token": "do-not-project", "password": "do-not-project"}
    result = normalize_tool_result("lab_synthetic_role_lease", parsed, "raw", tool_result_id=17)
    assert len(result) == 1 and result[0]["evidence_type"] == "synthetic_role_lease"
    assert "do-not-project" not in str(result)
    with pytest.raises(ValueError):
        normalize_tool_result("lab_synthetic_role_lease", {**parsed, "state_sha256": "bad"}, "raw")


def test_l4_depth_boundaries_and_profile_catalog(monkeypatch):
    from app.attack_authorization import depth_decision

    contracts, worker = _modules(monkeypatch)
    assert depth_decision(1, 4)["reason_code"] == "ATTACK_DEPTH_EXCEEDED"
    assert depth_decision(3, 4)["reason_code"] == "ATTACK_DEPTH_EXCEEDED"
    assert depth_decision(7, 4)["passed"] is True
    bridge_path = (Path(__file__).resolve().parents[1] / "experiments" /
                   "gade-seven-level-v1" / "l3-action" / "codex_agent_bridge.py")
    monkeypatch.setenv("GADE_L3_PROTOCOL", "GADE_BC_D1_D3_EXPLORATORY_V1")
    monkeypatch.setenv("GADE_L4_SYNTHETIC_ENABLED", "1")
    spec = importlib.util.spec_from_file_location("l4_bridge_bc", bridge_path)
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    assert "lab.synthetic_role_lease.v1" not in {
        row["action_id"] for row in bridge.build_action_catalog(worker.effective_allowed_tools())}
    monkeypatch.setenv("GADE_L3_PROTOCOL", "GADE_A_L4_ENGINEERING_V1")
    spec = importlib.util.spec_from_file_location("l4_bridge_a", bridge_path)
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    rows = {row["action_id"]: row for row in bridge.build_action_catalog(worker.effective_allowed_tools())}
    assert rows["lab.synthetic_role_lease.v1"]["required_depth"] == 4
    assert rows["lab.synthetic_role_lease.v1"]["parameter_schema"] == contracts.ACTION_PARAMETER_SCHEMAS["lab.synthetic_role_lease.v1"]


@pytest.mark.asyncio
@pytest.mark.parametrize("depth", [1, 3])
async def test_l4_gade_depth_denial_creates_no_grant_or_task(monkeypatch, depth):
    from app.execution_governance import evaluate_and_authorize
    from app.models import Target

    contracts, _ = _modules(monkeypatch)
    action_id = "lab.synthetic_role_lease.v1"
    target = Target(id=17, target="127.0.0.1", target_type="ip", scope="127.0.0.1/32")
    target.authorization_depth = depth
    action = SimpleNamespace(action_id=action_id, validation_tier=4,
        execution_identity=contracts.ACTION_IDENTITIES[action_id],
        template_version=contracts.ACTION_TEMPLATES[action_id])

    class Session:
        def __init__(self):
            self.added = []

        def add(self, value):
            self.added.append(value)

        async def flush(self):
            for index, value in enumerate(self.added, 1):
                if getattr(value, "id", None) is None:
                    value.id = index

        async def execute(self, _statement):
            return SimpleNamespace(scalar_one_or_none=lambda: action)

    db = Session()
    params = contracts.canonical_action_parameters(action_id=action_id, target="127.0.0.1",
        port=18080, protocol="tcp", service="http")
    result = await evaluate_and_authorize(db, target=target,
        tool_name="lab_synthetic_role_lease", parameters=params,
        reason="fixed engineering depth test", confidence=1.0, provider="test",
        authorization_source="engineering", evidence_refs=[])
    assert result.evaluation.outcome == "DENY"
    assert result.evaluation.contract_snapshot["reason_code"] == "ATTACK_DEPTH_EXCEEDED"
    assert result.authorization is None
    assert not any(type(row).__name__ in {"ExecutionAuthorization", "ToolTask"} for row in db.added)
