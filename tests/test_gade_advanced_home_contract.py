"""Run in a separate process with GADE_HOME_LAB_EXPLORATORY=1."""

import json
import importlib.util
import secrets
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app import action_contracts as contracts
from app.attack_authorization import depth_decision
from app.execution_governance import evaluate_and_authorize
from app.execution_trace import context_evidence
from app.models import Target
from worker.evidence_normalizer import normalize_tool_result


pytestmark = pytest.mark.skipif(not contracts.HOME_LAB_EXPLORATORY, reason="home-only contract")


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


def test_manifest_matches_registry_and_fixed_scope():
    path = Path(__file__).resolve().parents[1] / "home-lab" / "action-contracts" / "advanced-synthetic-v1.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    assert manifest["status"] == "STATIC_CANDIDATE_DISABLED_BY_DEFAULT"
    assert len(manifest["actions"]) == len(contracts.HOME_ADVANCED_ACTIONS) == 8
    for row in manifest["actions"]:
        action, depth, fixed_path = contracts.HOME_ADVANCED_ACTIONS[row["tool"]]
        assert (row["action_id"], row["depth"], row["path"]) == (action, depth, f"/lab/advanced/{fixed_path}")
        assert contracts.ACTION_REQUIRED_ATTACK_DEPTH[action] == depth
        params = contracts.canonical_action_parameters(action_id=action,
            target="127.0.0.1", port=18080, protocol="tcp", service="http")
        assert params["action_path"] == row["path"] and params["request_body"] == {}
        assert depth_decision(1, depth)["reason_code"] == "ATTACK_DEPTH_EXCEEDED"
        assert depth_decision(3, depth)["reason_code"] == "ATTACK_DEPTH_EXCEEDED"
        assert depth_decision(7, depth)["passed"] is True
        with pytest.raises(ValueError):
            contracts.canonical_action_parameters(action_id=action,
                target="192.0.2.10", port=18080, protocol="tcp", service="http")


@pytest.mark.asyncio
@pytest.mark.parametrize("tool,spec", list(contracts.HOME_ADVANCED_ACTIONS.items()) + [
    ("lab_synthetic_role_lease", ("lab.synthetic_role_lease.v1", 4, "l4-role-lease"))])
async def test_depth_and_approval_gate_for_every_advanced_action(tool, spec):
    action_id, depth, _path = spec
    action = SimpleNamespace(action_id=action_id, validation_tier=depth, enabled=True,
        execution_identity=contracts.ACTION_IDENTITIES[action_id],
        template_version=contracts.ACTION_TEMPLATES[action_id])
    params = contracts.canonical_action_parameters(action_id=action_id,
        target="127.0.0.1", port=18080, protocol="tcp", service="http")
    for authorized_depth, expected in ((1, "DENY"), (3, "DENY")):
        target = Target(id=17, target="127.0.0.1", target_type="ip", scope="127.0.0.1/32")
        target.authorization_depth = authorized_depth
        db = FakeSession(action)
        result = await evaluate_and_authorize(db, target=target, tool_name=tool,
            parameters=params, reason="fixed offline governance contract", confidence=1.0,
            provider="test", authorization_source="engineering",
            evidence_refs=context_evidence(target))
        assert result.evaluation.outcome == expected
        assert result.authorization is None
        assert not any(type(row).__name__ in {"ExecutionAuthorization", "ToolTask"} for row in db.added)
        if expected == "DENY":
            assert result.evaluation.contract_snapshot["reason_code"] == "ATTACK_DEPTH_EXCEEDED"
    target.authorization_depth = 7
    db = FakeSession(action)
    at_ceiling = await evaluate_and_authorize(db, target=target, tool_name=tool,
        parameters=params, reason="fixed offline governance contract", confidence=1.0,
        provider="test", authorization_source="engineering",
        evidence_refs=context_evidence(target))
    policy_managed = tool in contracts.HOME_ADVANCED_ACTIONS or action_id == "lab.synthetic_role_lease.v1"
    if policy_managed:
        assert at_ceiling.evaluation.outcome == "DENY"
        assert at_ceiling.evaluation.contract_snapshot["reason_code"] in {
            "AUTONOMOUS_ACTION_NOT_ALLOWLISTED", "AUTONOMOUS_POLICY_NOT_ENABLED",
            "TARGET_IDENTITY_UNVERIFIED",
        }
    else:
        assert at_ceiling.evaluation.outcome == "PENDING"
    assert at_ceiling.authorization is None
    assert not any(type(row).__name__ in {"ExecutionAuthorization", "ToolTask"} for row in db.added)
    db = FakeSession(action)
    unreviewed = await evaluate_and_authorize(db, target=target, tool_name=tool,
        parameters=params, reason="fixed offline governance contract", confidence=1.0,
        provider="test", authorization_source="engineering",
        human_approved_by="legacy-approval-must-not-expand-candidate-policy", ttl_seconds=60,
        evidence_refs=context_evidence(target))
    if policy_managed:
        assert unreviewed.evaluation.outcome == "DENY"
        assert unreviewed.authorization is None
    else:
        assert unreviewed.evaluation.outcome == "ALLOW"
        assert unreviewed.authorization.human_approved_by == "legacy-approval-must-not-expand-candidate-policy"


def test_worker_advanced_capability_disabled_until_explicit_flag(monkeypatch):
    import kali_worker.app as worker

    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", "127.0.0.1/32")
    monkeypatch.delenv("GADE_ADVANCED_SYNTHETIC_ENABLED", raising=False)
    assert set(contracts.HOME_ADVANCED_ACTIONS).isdisjoint(worker.effective_allowed_tools())
    monkeypatch.setenv("GADE_ADVANCED_SYNTHETIC_ENABLED", "1")
    assert set(contracts.HOME_ADVANCED_ACTIONS).issubset(worker.effective_allowed_tools())
    monkeypatch.setenv("GADE_L2_TEST_USERNAME", "lab-user")
    monkeypatch.setenv("GADE_L2_TEST_PASSWORD", "unit-test-password-not-real-123456789")
    tool = "lab_synthetic_canary_access"
    action = contracts.ACTION_BY_TOOL[tool]
    req = worker.ExecuteRequest(tool=tool, target="127.0.0.1", port=18080,
        protocol="tcp", service="http", action_id=action,
        correlation_id="GADE-L3-MULTI-A-R01-abcdef123456",
        authorization_parameters={"target": "127.0.0.1"})
    assert worker.run_lab_advanced_synthetic(req)["status"] == "failed"


def test_worker_fixed_handlers_reach_only_synthetic_target_and_return_safe_effects(monkeypatch, tmp_path):
    import kali_worker.app as worker

    target_path = Path(__file__).resolve().parents[1] / "lab" / "mode-b-target" / "l2_auth.py"
    spec = importlib.util.spec_from_file_location("advanced_worker_target", target_path)
    target = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(target)
    password, reset_key = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    state = target.AuthState("lab-user", password, reset_key, state_dir=tmp_path,
                             enable_advanced=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), target.Handler)
    server.auth_state = state
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    original_connection = worker.http.client.HTTPConnection

    class Redirect(original_connection):
        def __init__(self, host, port=None, *args, **kwargs):
            assert host == "127.0.0.1" and port == 18080
            super().__init__("127.0.0.1", server.server_port, *args, **kwargs)

    try:
        monkeypatch.setattr(worker.http.client, "HTTPConnection", Redirect)
        monkeypatch.setenv("GADE_ADVANCED_SYNTHETIC_ENABLED", "1")
        monkeypatch.setenv("GADE_L2_TEST_USERNAME", "lab-user")
        monkeypatch.setenv("GADE_L2_TEST_PASSWORD", password)
        for tool, (action, depth, path) in contracts.HOME_ADVANCED_ACTIONS.items():
            req = worker.ExecuteRequest(tool=tool, target="127.0.0.1", port=18080,
                protocol="tcp", service="http", action_id=action,
                request_id=str(uuid4()), correlation_id="GADE-L3-MULTI-A-R01-abcdef123456",
                authorization_parameters=contracts.canonical_action_parameters(
                    action_id=action, target="127.0.0.1", port=18080,
                    protocol="tcp", service="http"))
            result = worker.run_lab_advanced_synthetic(req)
            assert result["status"] == "completed", (tool, result)
            assert result["parsed_result"]["action"] == path
            assert password not in result["raw_output"]
            proof = state.inspect_advanced("abcdef123456", req.correlation_id, req.request_id)
            assert proof["events"] and proof["state_sha256"] == result["parsed_result"]["state_sha256"]
        assert state.reset(reset_key, "reset", "case") is True
        assert not state.advanced_state_path.exists()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


@pytest.mark.parametrize("tool,spec", list(contracts.HOME_ADVANCED_ACTIONS.items()))
def test_advanced_normalizer_requires_exact_reviewed_effect(tool, spec):
    action, depth, path = spec
    effects = {
        "l5-canary": {"canary_id": "LAB-CANARY-NONSECRET-01"},
        "l5-visibility": {"control_simulation": "degraded_visibility", "real_security_controls_changed": False},
        "l6-discovery": {"node_ids": ["node-alpha", "node-beta"]},
        "l6-session": {"source_node": "node-alpha", "destination_node": "node-beta"},
        "l7-collection": {"record_ids": ["SYNTHETIC-RECORD-1", "SYNTHETIC-RECORD-2"]},
        "l7-c2": {"message": "LAB-NOOP", "ack": "LAB-NOOP-ACK"},
        "l7-transfer": {"receiver_id": "lab-receiver-fixed", "external_network_used": False,
                        "payload_sha256": "a" * 64},
        "l7-impact": {"impact_mode": "simulated_interruption", "real_service_interrupted": False},
    }
    parsed = {"success": True, "status": "done", "test_case_id": "GADE-L3-MULTI-A-R01-abcdef123456",
              "action": path, "action_http_status": 200, "state_sha256": "b" * 64,
              "effect": effects[path], "simulation": True, "session_token": "never-copy-this"}
    result = normalize_tool_result(tool, parsed, "raw", SimpleNamespace(host="127.0.0.1", port=18080, service="http"), 1)
    assert len(result) == 1 and result[0]["details"]["required_depth"] == depth
    assert "never-copy-this" not in str(result)
    with pytest.raises(ValueError):
        normalize_tool_result(tool, {**parsed, "effect": {"unexpected": True}}, "raw")
