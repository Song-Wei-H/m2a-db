import socket
import hashlib
from uuid import uuid4

from app.execution_governance import parameter_hash

from fastapi.testclient import TestClient

from kali_worker import app as worker


def test_health_declares_evidence_tools_and_external_scope_policy():
    body = TestClient(worker.app).get("/health").json()
    assert body["status"] == "ok"
    assert body["scope_policy"] == "external_network_controls"
    assert body["scope_enforced_by_worker"] is False
    assert len(body["build_sha256"]) == 64
    assert {"tls_certificate", "http_security_headers", "dns_metadata"}.issubset(body["allowed_tools"])


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
