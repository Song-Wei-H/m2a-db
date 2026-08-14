import socket

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
