import socket
import hashlib
import json
import pytest
from pathlib import Path
from uuid import uuid4

from app.execution_governance import parameter_hash

from fastapi.testclient import TestClient

from app.config import Settings
from kali_worker import app as worker


def test_health_declares_evidence_tools_and_external_scope_policy():
    body = TestClient(worker.app).get("/health").json()
    assert body["status"] == "ok"
    assert body["scope_policy"] == "external_network_controls"
    assert body["scope_enforced_by_worker"] is False
    assert len(body["build_sha256"]) == 64
    assert {"tls_certificate", "http_security_headers", "dns_metadata"}.issubset(body["allowed_tools"])


def test_isolated_profile_health_requires_and_reports_explicit_scope(monkeypatch):
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", "172.29.4.10/32")
    monkeypatch.setenv("GADE_NUCLEI_ACTION_ENABLED", "false")
    body = TestClient(worker.app).get("/health").json()
    assert body["scope_enforced_by_worker"] is True
    assert body["scope_policy"] == "worker_enforced_cidr"
    assert body["allowed_scopes"] == ["172.29.4.10/32"]
    assert "dirb_safe" not in body["allowed_tools"]
    assert "nuclei_safe" not in body["allowed_tools"]
    assert len(body["registered_tools"]) == 10
    assert "lab_valid_account_access" in body["registered_tools"]
    assert "lab_fixed_python_execution" in body["registered_tools"]
    assert len(body["allowed_tools"]) == 9
    assert "lab_fixed_python_execution" in body["allowed_tools"]
    assert body["unavailable_actions"][0]["action_id"] == "nuclei.safe_scan.v1"


def test_nuclei_action_is_unavailable_without_approved_bundle_and_never_calls_handler(monkeypatch):
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("GADE_NUCLEI_ACTION_ENABLED", "false")
    monkeypatch.setattr(worker, "run_nuclei", lambda *args, **kwargs: pytest.fail(
        "unavailable Nuclei action reached its handler"))
    response = TestClient(worker.app).post("/execute", json={
        "tool": "nuclei_safe", "target": "172.29.4.10", "port": 8080,
        "action_id": "nuclei.safe_scan.v1",
    })
    assert response.json() == {
        "status": "unavailable",
        "reason": "nuclei.safe_scan.v1 unavailable: no approved template bundle is installed",
        "tool": "nuclei_safe",
        "action_id": "nuclei.safe_scan.v1",
    }


def test_nuclei_bundle_manifest_must_be_nonempty_and_hash_exact(monkeypatch):
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("GADE_NUCLEI_ACTION_ENABLED", "true")
    manifest = Path("test-approved-nuclei-manifest.json")
    original_read_text = Path.read_text
    def read_empty_manifest(path, *args, **kwargs):
        if path == manifest:
            return json.dumps({"approval_status": "APPROVED", "templates": []})
        return original_read_text(path, *args, **kwargs)
    monkeypatch.setattr(Path, "read_text", read_empty_manifest)
    monkeypatch.setenv("GADE_NUCLEI_TEMPLATE_MANIFEST", str(manifest))
    available, reason = worker.nuclei_action_state()
    assert available is False
    assert reason == "nuclei.safe_scan.v1 unavailable: approved template manifest is missing or empty"


def test_nuclei_info_template_cannot_replace_critical_high_contract(monkeypatch):
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("GADE_NUCLEI_ACTION_ENABLED", "true")
    manifest = Path("proposed-info-template-manifest.json")
    payload = {
        "approval_status": "APPROVED",
        "severity_selector": "critical,high",
        "selection_mode": "complete-severity-selector",
        "runtime_loaded_count": 1,
        "templates": [{"path": "http/header.yaml", "severity": "info", "sha256": "0" * 64}],
    }
    original_read_text = Path.read_text
    def read_info_manifest(path, *args, **kwargs):
        if path == manifest:
            return json.dumps(payload)
        return original_read_text(path, *args, **kwargs)
    monkeypatch.setattr(Path, "read_text", read_info_manifest)
    monkeypatch.setenv("GADE_NUCLEI_TEMPLATE_MANIFEST", str(manifest))
    available, reason = worker.nuclei_action_state()
    assert available is False
    assert reason == "nuclei.safe_scan.v1 unavailable: template severity is outside the fixed critical,high selector"


def test_isolated_profile_fails_closed_when_scope_is_missing(monkeypatch):
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.delenv("KALI_WORKER_ALLOWED_SCOPES", raising=False)
    response = TestClient(worker.app, raise_server_exceptions=False).get("/health")
    assert response.status_code == 500


def test_isolated_worker_scope_rejects_external_target_before_handler(monkeypatch):
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", "172.29.4.10/32")
    monkeypatch.setattr(worker, "run_http_security_headers", lambda *args, **kwargs: pytest.fail(
        "out-of-scope request reached the action handler"))
    action = "http_security_headers.collect.v1"
    req = worker.ExecuteRequest(tool="http_security_headers", target="192.0.2.10",
                                port=8080, protocol="tcp", service="http", action_id=action)
    parameters = worker.canonical_parameters(req)
    response = TestClient(worker.app).post("/execute", json={
        **req.model_dump(),
        "execution_identity": worker.ACTION_IDENTITIES[action],
        "authorization_parameters": parameters,
        "authorization_parameters_hash": parameter_hash(parameters),
        "template_id": worker.ACTION_TEMPLATES[action],
        "task_id": 1,
        "authorization_id": 1,
        "request_id": str(uuid4()),
        "correlation_id": str(uuid4()),
        "expected_worker_build_sha256": worker.WORKER_BUILD_SHA256,
    })
    assert response.json() == {
        "status": "rejected", "reason": "target outside allowed Worker scope",
        "tool": "http_security_headers",
    }


def test_isolated_profile_rejects_tool_without_formal_action_contract(monkeypatch):
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", "172.29.4.10/32")
    response = TestClient(worker.app).post("/execute", json={
        "tool": "dirb_safe", "target": "172.29.4.10", "port": 8080,
    })
    assert response.json() == {
        "status": "rejected", "reason": "tool not allowed", "tool": "dirb_safe",
    }


def test_isolated_profile_requires_governed_request_metadata(monkeypatch):
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", "172.29.4.10/32")
    req = worker.ExecuteRequest(tool="http_security_headers", target="172.29.4.10",
                                port=8080, protocol="tcp", service="http",
                                action_id="http_security_headers.collect.v1")
    parameters = worker.canonical_parameters(req)
    response = TestClient(worker.app).post("/execute", json={
        **req.model_dump(),
        "execution_identity": worker.ACTION_IDENTITIES[req.action_id],
        "authorization_parameters": parameters,
        "authorization_parameters_hash": parameter_hash(parameters),
        "template_id": worker.ACTION_TEMPLATES[req.action_id],
    })
    assert response.json() == {
        "status": "rejected",
        "reason": "isolated profile requires governed execution metadata",
        "tool": "http_security_headers",
    }


def test_isolated_worker_accepts_only_addresses_in_cidr(monkeypatch):
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", "172.29.4.10/32")
    worker.validate_worker_target_scope(["172.29.4.10"])
    with pytest.raises(ValueError, match="outside allowed Worker scope"):
        worker.validate_worker_target_scope(["172.29.4.10", "192.0.2.10"])


def test_isolated_worker_rejects_hostnames_without_dns_resolution(monkeypatch):
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", "172.29.4.10/32")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: pytest.fail(
        "isolated Worker must not resolve hostnames"))
    with pytest.raises(ValueError, match="accepts IP literals only"):
        worker.validate_worker_target_literal("example.test")


def test_m2a_worker_endpoint_and_scope_are_environment_configurable(monkeypatch):
    monkeypatch.setenv("KALI_WORKER_URL", "http://127.0.0.1:18081")
    monkeypatch.setenv("ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("ALLOWED_SCOPES", "172.29.4.10/32")
    configured = Settings(_env_file=None, database_url="postgresql+asyncpg://test:test@localhost/test")
    assert configured.kali_worker_url == "http://127.0.0.1:18081"
    assert configured.enforce_target_scope is True
    assert configured.allowed_scopes_list == ["172.29.4.10/32"]


def test_dns_metadata_returns_resolved_addresses(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0)),
    ])
    monkeypatch.setattr(socket, "getfqdn", lambda target: "asset.example")
    req = worker.ExecuteRequest(tool="dns_metadata", target="asset.example",
                                action_id="dns.metadata_collect.v1")
    parameters = worker.canonical_parameters(req)
    body = TestClient(worker.app).post("/execute", json={
        **req.model_dump(),
        "execution_identity": worker.ACTION_IDENTITIES["dns.metadata_collect.v1"],
        "authorization_parameters": parameters,
        "authorization_parameters_hash": parameter_hash(parameters),
    }).json()
    assert body["status"] == "completed"
    assert body["parsed_result"]["addresses"] == [
        {"record_type": "A", "address": "192.0.2.10"}
    ]


def test_unknown_tool_is_rejected_before_resolution(monkeypatch):
    body = TestClient(worker.app).post(
        "/execute", json={"tool": "arbitrary_shell", "target": "192.0.2.10"}
    ).json()
    assert body == {"status": "rejected", "reason": "tool not allowed", "tool": "arbitrary_shell"}


def test_migrated_nuclei_requires_authorized_execution_identity():
    body = TestClient(worker.app).post(
        "/execute", json={"tool": "nuclei_safe", "target": "192.0.2.10"}
    ).json()
    assert body["status"] == "rejected"
    assert "authorization required" in body["reason"]


def test_nuclei_worker_executes_exact_authorized_identity(monkeypatch):
    captured = {}
    monkeypatch.setattr(worker, "resolve_target", lambda target: [target])
    monkeypatch.setattr(worker, "run_command", lambda command: captured.setdefault("result", {
        "status": "completed", "command": " ".join(command), "raw_output": ""
    }))
    parameters = worker.canonical_parameters(worker.ExecuteRequest(
        tool="nuclei_safe", target="192.0.2.10", port=443, protocol="tcp", service="https",
        action_id="nuclei.safe_scan.v1"))
    body = TestClient(worker.app).post("/execute", json={
        "tool": "nuclei_safe", "target": "192.0.2.10", "port": 443,
        "protocol": "tcp", "service": "https", "action_id": "nuclei.safe_scan.v1",
        "execution_identity": worker.ACTION_IDENTITIES["nuclei.safe_scan.v1"],
        "authorization_parameters": parameters,
        "authorization_parameters_hash": parameter_hash(parameters),
    }).json()
    assert body["status"] == "completed"
    assert body["command"].split() == ["nuclei", "-u", "https://192.0.2.10:443/", "-severity",
        "critical,high", "-rl", "5", "-timeout", "5", "-retries", "0", "-no-color"]


def test_governed_builtin_receipt_correlates_request_and_records_application_failure(monkeypatch):
    action = "http_security_headers.collect.v1"
    request_id = str(uuid4())
    parameters = worker.canonical_parameters(worker.ExecuteRequest(
        tool="http_security_headers", target="192.0.2.10", port=18080,
        protocol="tcp", service="http", action_id=action))
    body = {
        "tool": "http_security_headers", "target": "192.0.2.10", "port": 18080,
        "protocol": "tcp", "service": "http", "action_id": action,
        "execution_identity": worker.ACTION_IDENTITIES[action],
        "authorization_parameters": parameters,
        "authorization_parameters_hash": parameter_hash(parameters),
        "task_id": 31, "authorization_id": 41, "request_id": request_id,
        "template_id": worker.ACTION_TEMPLATES[action],
        "expected_worker_build_sha256": worker.WORKER_BUILD_SHA256,
    }
    monkeypatch.setattr(worker, "resolve_target", lambda target: [target])
    monkeypatch.setattr(worker, "run_http_security_headers", lambda *args: {
        "status": "failed", "command": "builtin:http_security_headers",
        "raw_output": "", "parsed_result": {"success": False, "error": "connect failed"},
    })
    response = TestClient(worker.app).post("/execute", json=body)
    result = response.json()
    receipt = result["execution_receipt"]
    assert response.status_code == 200  # transport success does not mean action success
    assert result["status"] == "failed"
    assert receipt["request_id"] == request_id
    assert receipt["task_id"] == 31 and receipt["authorization_id"] == 41
    assert receipt["template_id"] == worker.ACTION_TEMPLATES[action]
    assert receipt["worker_build_sha256"] == worker.WORKER_BUILD_SHA256
    assert receipt["handler_invoked"] is True
    assert receipt["execution_outcome"] == "failed" and receipt["action_success"] is False
    assert receipt["execution_kind"] == "builtin_handler"
    assert receipt["process_started_at_utc"] is None
    assert len(receipt["process_output_sha256"]) == 64
    assert receipt["request_received_at_utc"] <= receipt["handler_started_at_utc"] <= receipt["handler_completed_at_utc"]


def test_governed_worker_requires_request_and_template_correlation():
    action = "http_security_headers.collect.v1"
    parameters = worker.canonical_parameters(worker.ExecuteRequest(
        tool="http_security_headers", target="192.0.2.10", port=18080,
        protocol="tcp", service="http", action_id=action))
    response = TestClient(worker.app).post("/execute", json={
        "tool": "http_security_headers", "target": "192.0.2.10", "port": 18080,
        "protocol": "tcp", "service": "http", "action_id": action,
        "execution_identity": worker.ACTION_IDENTITIES[action],
        "authorization_parameters": parameters,
        "authorization_parameters_hash": parameter_hash(parameters),
        "task_id": 31, "authorization_id": 41,
        "expected_worker_build_sha256": worker.WORKER_BUILD_SHA256,
    })
    assert response.status_code == 200
    assert response.json()["status"] == "rejected"
    assert response.json()["reason"] == "governed request correlation fields missing"


def test_run_command_records_process_exit_and_output_hashes(monkeypatch):
    class FakeProcess:
        pid = 12345
        returncode = 7

        def poll(self):
            return self.returncode

        def communicate(self, timeout):
            return "safe stdout", "safe stderr"

    monkeypatch.setattr(worker.subprocess, "Popen", lambda *args, **kwargs: FakeProcess())
    result = worker.run_command(["fixed-tool", "--version"])
    assert result["status"] == "failed"
    assert result["returncode"] == 7
    assert result["process_pid"] == 12345
    assert result["process_started_at_utc"] <= result["process_completed_at_utc"]
    assert result["stdout_sha256"] == hashlib.sha256(b"safe stdout").hexdigest()
    assert result["stderr_sha256"] == hashlib.sha256(b"safe stderr").hexdigest()


def test_worker_rejects_parameter_or_action_substitution(monkeypatch):
    monkeypatch.setattr(worker, "resolve_target", lambda target: [target])
    parameters = {"port": 443, "protocol": "tcp", "service": "https", "target": "192.0.2.11"}
    body = TestClient(worker.app).post("/execute", json={
        "tool": "nuclei_safe", "target": "192.0.2.10", "port": 443,
        "protocol": "tcp", "service": "https", "action_id": "nuclei.safe_scan.v1",
        "execution_identity": worker.ACTION_IDENTITIES["nuclei.safe_scan.v1"],
        "authorization_parameters": parameters,
        "authorization_parameters_hash": parameter_hash(parameters),
    }).json()
    assert body["status"] == "rejected"
    assert "parameter identity mismatch" in body["reason"]
