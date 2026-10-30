import os
import subprocess
import sys
from pathlib import Path

import yaml


def test_office_approved_dispatch_tools_require_explicit_run_allowlist(monkeypatch):
    from app.config import settings
    from app.security.tool_policy import resolve_template_tool
    from app.tool_catalog import CANONICAL_ALLOWED_TOOLS
    import pytest

    monkeypatch.setattr(settings, "allowed_tools", ",".join(sorted(CANONICAL_ALLOWED_TOOLS)))
    for action_tool in ("lab_synthetic_role_lease", "lab_synthetic_canary_access", "lab_synthetic_node_discovery", "lab_synthetic_collection", "lab_synthetic_receiver_transfer"):
        assert action_tool not in CANONICAL_ALLOWED_TOOLS
        with pytest.raises(ValueError, match="ALLOWED_TOOLS"):
            resolve_template_tool(action_tool)
        monkeypatch.setattr(settings, "allowed_tools", settings.allowed_tools + "," + action_tool)
        assert resolve_template_tool(action_tool) == action_tool


def test_office_l6_discovery_normalizer_requires_separate_component_proof():
    env = os.environ.copy()
    env.update({"GADE_OFFICE_DOCKER_LAB": "1", "GADE_OFFICE_DOCKER_LAB_TARGET": "192.0.2.119",
                "GADE_OFFICE_DOCKER_LAB_PORT": "18081", "GADE_L4_SYNTHETIC_ENABLED": "1",
                "GADE_ADVANCED_SYNTHETIC_ENABLED": "1"})
    script = r'''
from types import SimpleNamespace
from worker.evidence_normalizer import normalize_tool_result
parsed = {"success": True, "status": "done", "test_case_id": "GADE-L3-MULTI-A-R01-abcdef123456",
          "action": "l6-discovery", "action_http_status": 200, "simulation": True,
          "state_sha256": "a" * 64,
          "effect": {"node_ids": ["node-alpha", "node-beta"],
                     "component_event_ids": ["a" * 32, "b" * 32],
                     "component_state_sha256": {"node-alpha": "c" * 64, "node-beta": "d" * 64},
                     "separate_processes_verified": True}}
ctx = SimpleNamespace(host="192.0.2.119", port=18081, service="http")
assert normalize_tool_result("lab_synthetic_node_discovery", parsed, "raw", ctx, 1)[0]["evidence_type"] == "synthetic_advanced_effect"
for bad in ({"node_ids": ["node-alpha", "node-beta"]},
            {**parsed["effect"], "component_event_ids": ["a" * 32, "a" * 32]},
            {**parsed["effect"], "extra": True}):
    try: normalize_tool_result("lab_synthetic_node_discovery", {**parsed, "effect": bad}, "raw", ctx, 1)
    except ValueError: pass
    else: raise AssertionError("invalid L6 component proof accepted")
print("OFFICE_L6_NORMALIZATION=PASS")
'''
    result = subprocess.run([sys.executable, "-B", "-c", script], env=env,
                            capture_output=True, text=True, timeout=15, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OFFICE_L6_NORMALIZATION=PASS" in result.stdout


def test_office_l7_receiver_normalizer_requires_independent_no_egress_proof():
    env = os.environ.copy()
    env.update({"GADE_OFFICE_DOCKER_LAB": "1", "GADE_OFFICE_DOCKER_LAB_TARGET": "192.0.2.119",
                "GADE_OFFICE_DOCKER_LAB_PORT": "18081", "GADE_L4_SYNTHETIC_ENABLED": "1",
                "GADE_ADVANCED_SYNTHETIC_ENABLED": "1"})
    script = r'''
from types import SimpleNamespace
from worker.evidence_normalizer import normalize_tool_result
parsed = {"success": True, "status": "done", "test_case_id": "GADE-L3-MULTI-A-R01-abcdef123456",
          "action": "l7-transfer", "action_http_status": 200, "simulation": True,
          "state_sha256": "a" * 64,
          "effect": {"receiver_id": "lab-receiver-fixed", "external_network_used": False,
                     "payload_sha256": "b" * 64, "receiver_event_id": "c" * 32,
                     "receiver_state_sha256": "d" * 64, "separate_processes_verified": True}}
ctx = SimpleNamespace(host="192.0.2.119", port=18081, service="http")
assert normalize_tool_result("lab_synthetic_receiver_transfer", parsed, "raw", ctx, 1)[0]["evidence_type"] == "synthetic_advanced_effect"
for bad in ({**parsed["effect"], "external_network_used": True},
            {**parsed["effect"], "receiver_event_id": "bad"},
            {**parsed["effect"], "extra": True}):
    try: normalize_tool_result("lab_synthetic_receiver_transfer", {**parsed, "effect": bad}, "raw", ctx, 1)
    except ValueError: pass
    else: raise AssertionError("invalid L7 receiver proof accepted")
print("OFFICE_L7_NORMALIZATION=PASS")
'''
    result = subprocess.run([sys.executable, "-B", "-c", script], env=env,
                            capture_output=True, text=True, timeout=15, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OFFICE_L7_NORMALIZATION=PASS" in result.stdout


def test_office_d7_profile_is_fixed_and_explicitly_enabled():
    env = os.environ.copy()
    env.update({
        "DATABASE_URL": "postgresql+asyncpg://test:test@127.0.0.1:1/gade_l7_offline",
        "GADE_HOME_LAB_EXPLORATORY": "0",
        "GADE_OFFICE_DOCKER_LAB": "1",
        "GADE_OFFICE_DOCKER_LAB_TARGET": "192.0.2.119",
        "GADE_OFFICE_DOCKER_LAB_PORT": "18081",
        "GADE_L4_SYNTHETIC_ENABLED": "1",
        "GADE_ADVANCED_SYNTHETIC_ENABLED": "1",
        "GADE_L3_PROTOCOL": "GADE_A_D7_OFFICE_SYNTHETIC_V1",
        "KALI_WORKER_PROFILE": "gade-experiment",
        "KALI_WORKER_ENFORCE_TARGET_SCOPE": "true",
        "KALI_WORKER_ALLOWED_SCOPES": "192.0.2.119/32",
    })
    script = r'''
from app import action_contracts as c
from kali_worker import app as w
assert c.OFFICE_DOCKER_LAB and not c.HOME_LAB_EXPLORATORY
assert c.LAB_TARGET == "192.0.2.119" and c.LAB_PORT == 18081
for tool, (action, depth, _path) in c.HOME_ADVANCED_ACTIONS.items():
    assert c.ACTION_REQUIRED_ATTACK_DEPTH[action] == depth
    assert tool in w.effective_allowed_tools()
    params = c.canonical_action_parameters(action_id=action, target=c.LAB_TARGET,
        port=c.LAB_PORT, protocol="tcp", service="http")
    assert params["target"] == c.LAB_TARGET and params["port"] == c.LAB_PORT
    try:
        c.canonical_action_parameters(action_id=action, target=c.LAB_TARGET,
            port=18080, protocol="tcp", service="http")
    except ValueError:
        pass
    else:
        raise AssertionError("office Action accepted an unapproved port")
enabled, scopes = w.worker_scope_configuration()
assert enabled and [str(item) for item in scopes] == ["192.0.2.119/32"]
print("OFFICE_PROFILE_CONTRACT=PASS actions=8 target=192.0.2.119 port=18081 scope=/32")
'''
    result = subprocess.run([sys.executable, "-B", "-c", script], env=env,
                            capture_output=True, text=True, timeout=15, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OFFICE_PROFILE_CONTRACT=PASS" in result.stdout

def test_office_d7_compose_gateway_uses_bounded_ingress():
    repo = Path(__file__).parents[1]
    compose_template = (repo / "compose.gade-a-d7.template.yml").read_text(encoding="utf-8")
    assert "${GADE_A_D7_HOST_BIND_IP:?set local bind IP}" in compose_template
    compose = yaml.safe_load(compose_template.replace(
        "${GADE_A_D7_HOST_BIND_IP:?set local bind IP}", "192.0.2.10"
    ).replace("${GADE_A_D7_HOST_PORT:-18081}", "18081").replace(
        "${GADE_A_D7_INGRESS_SUBNET:?set ingress subnet}", "172.30.240.0/24"
    ).replace("${GADE_A_D7_INGRESS_GATEWAY:?set ingress gateway}", "172.30.240.1"))
    networks = compose["networks"]
    assert networks["gade-a-d7-internal"]["internal"] is True
    ingress = networks["gade-a-d7-ingress"]
    assert ingress["driver"] == "bridge"
    assert ingress["internal"] is False
    assert ingress["attachable"] is False
    assert ingress["ipam"]["config"] == [{"subnet": "172.30.240.0/24", "gateway": "172.30.240.1"}]
    assert ingress["driver_opts"] == {
        "com.docker.network.bridge.enable_ip_masquerade": "false",
        "com.docker.network.bridge.enable_icc": "false",
    }
    ingress_users = sorted(
        name for name, service in compose["services"].items()
        if "gade-a-d7-ingress" in service.get("networks", [])
    )
    assert ingress_users == ["target-gateway"]
    assert compose["services"]["target-gateway"]["ports"] == [
        "192.0.2.10:18081:8080"
    ]
    nginx = (repo / "lab" / "mode-b-target" / "nginx.gade-a-d7.conf.template").read_text(encoding="utf-8")
    assert "allow __GADE_A_D7_WORKER_SOURCE_IP__;" in nginx
    assert "allow __GADE_A_D7_HOST_SOURCE_IP__;" in nginx
    assert "allow __GADE_A_D7_INGRESS_GATEWAY__;" in nginx
    assert "deny all;" in nginx


def test_office_l7_operator_sequence_is_fixed_and_requires_verified_collection_feedback():
    env = os.environ.copy()
    env.update({
        "GADE_HOME_LAB_EXPLORATORY": "0",
        "DATABASE_URL": "postgresql+asyncpg://test:test@127.0.0.1:1/gade_l7_offline",
        "GADE_OFFICE_DOCKER_LAB": "1",
        "GADE_OFFICE_DOCKER_LAB_TARGET": "192.0.2.119",
        "GADE_OFFICE_DOCKER_LAB_PORT": "18081",
        "GADE_L4_SYNTHETIC_ENABLED": "1",
        "GADE_ADVANCED_SYNTHETIC_ENABLED": "1",
        "KALI_WORKER_PROFILE": "gade-experiment",
        "KALI_WORKER_ENFORCE_TARGET_SCOPE": "true",
        "KALI_WORKER_ALLOWED_SCOPES": "192.0.2.119/32",
    })
    script = r'''
import importlib.util
from pathlib import Path
p = Path("experiments/gade-seven-level-v1/l3-action/run_l3_d7_d1.py")
spec = importlib.util.spec_from_file_location("gade_l3_driver", p)
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)
validate = d.validate_office_operator_acceptance_step
sequence = "L7_COLLECTION_THEN_RECEIVER_TRANSFER_V1"
assert validate(sequence_id=sequence, round_number=1,
    action_id="lab.synthetic_collection.v1", completed_action_ids=[], feedback_contents=[],
    context_sequence_id=sequence, context_sequence_step=1) is None
feedback = {
    "action_id": "lab.synthetic_collection.v1", "authorization_decision": "ALLOW",
    "execution_authorization": {"id": "grant-1", "scope": "192.0.2.119/32", "execution_limit": 1, "consumed_count": 1},
    "tool_task": {"id": 11, "status": "completed"},
    "worker_receipt": {"request_id": "req-1", "task_id": 11, "action_id": "lab.synthetic_collection.v1", "authorization_id": "grant-1", "handler_invoked": True},
    "tool_result": {"id": 12, "success": True}, "trace": {"status": "COMPLETE", "issues": []},
    "normalized_result_id": 13, "office_blue_verification_file": "round-01-target-blue-verification.json",
    "blue_alert_ids_verified": ["alert-1"],
    "target_events": [{"event": "l7_collection_created", "request_id": "req-1"}],
}
assert validate(sequence_id=sequence, round_number=2,
    action_id="lab.synthetic_receiver_transfer.v1", completed_action_ids=["lab.synthetic_collection.v1"],
    feedback_contents=[feedback], context_sequence_id=sequence, context_sequence_step=2) is None
def rejected(**kwargs):
    try:
        validate(**kwargs)
    except RuntimeError:
        return
    raise AssertionError("invalid L7 sequence accepted")
rejected(sequence_id=sequence, round_number=2, action_id="lab.synthetic_receiver_transfer.v1",
    completed_action_ids=[], feedback_contents=[], context_sequence_id=sequence, context_sequence_step=2)
rejected(sequence_id=sequence, round_number=2, action_id="lab.synthetic_collection.v1",
    completed_action_ids=["lab.synthetic_collection.v1"], feedback_contents=[feedback],
    context_sequence_id=sequence, context_sequence_step=2)
bad = {**feedback, "tool_result": {"id": 12, "success": False}}
rejected(sequence_id=sequence, round_number=2, action_id="lab.synthetic_receiver_transfer.v1",
    completed_action_ids=["lab.synthetic_collection.v1"], feedback_contents=[bad],
    context_sequence_id=sequence, context_sequence_step=2)
bad = {**feedback, "blue_alert_ids_verified": []}
rejected(sequence_id=sequence, round_number=2, action_id="lab.synthetic_receiver_transfer.v1",
    completed_action_ids=["lab.synthetic_collection.v1"], feedback_contents=[bad],
    context_sequence_id=sequence, context_sequence_step=2)
bad = {**feedback, "target_events": []}
rejected(sequence_id=sequence, round_number=2, action_id="lab.synthetic_receiver_transfer.v1",
    completed_action_ids=["lab.synthetic_collection.v1"], feedback_contents=[bad],
    context_sequence_id=sequence, context_sequence_step=2)
rejected(sequence_id="OTHER_SEQUENCE", round_number=1, action_id="lab.synthetic_collection.v1",
    completed_action_ids=[], feedback_contents=[], context_sequence_id="OTHER_SEQUENCE", context_sequence_step=1)
print("OFFICE_L7_OPERATOR_SEQUENCE=PASS")
'''
    result = subprocess.run([sys.executable, "-B", "-c", script], cwd=Path(__file__).parents[1], env=env,
                            capture_output=True, text=True, timeout=20, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OFFICE_L7_OPERATOR_SEQUENCE=PASS" in result.stdout
