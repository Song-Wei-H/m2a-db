import socket
from app.execution_governance import parameter_hash

from fastapi.testclient import TestClient

from kali_worker import app as worker


def test_health_declares_evidence_tools_and_external_scope_policy():
    body = TestClient(worker.app).get("/health").json()
    assert body["status"] == "ok"
    assert body["scope_policy"] == "external_network_controls"
    assert body["scope_enforced_by_worker"] is False
    assert {"tls_certificate", "http_security_headers", "dns_metadata"}.issubset(body["allowed_tools"])


def test_dns_metadata_returns_resolved_addresses(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0)),
    ])
    monkeypatch.setattr(socket, "getfqdn", lambda target: "asset.example")
    body = TestClient(worker.app).post(
        "/execute", json={"tool": "dns_metadata", "target": "asset.example"}
    ).json()
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
    parameters = {"port": 443, "protocol": "tcp", "service": "https", "target": "192.0.2.10"}
    body = TestClient(worker.app).post("/execute", json={
        "tool": "nuclei_safe", "target": "192.0.2.10", "port": 443,
        "protocol": "tcp", "service": "https", "action_id": "nuclei.safe_scan.v1",
        "execution_identity": worker.ACTION_IDENTITIES["nuclei.safe_scan.v1"],
        "authorization_parameters": parameters,
        "authorization_parameters_hash": parameter_hash(parameters),
    }).json()
    assert body["status"] == "completed"
    assert body["command"].split() == ["nuclei", "-u", "https://192.0.2.10:443", "-severity",
        "critical,high", "-rl", "5", "-timeout", "5", "-retries", "0", "-no-color"]


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
