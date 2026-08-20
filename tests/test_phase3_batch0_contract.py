from fastapi.testclient import TestClient

from app.action_contracts import ACTION_IDENTITIES, ACTION_TEMPLATES, canonical_action_parameters
from app.execution_governance import parameter_hash
from kali_worker import app as worker


def authorized_request(action_id: str, tool: str, target: str = "192.0.2.20") -> dict:
    parameters = canonical_action_parameters(
        action_id=action_id, target=target, port=443, protocol="tcp", service="https"
    )
    return {
        "tool": tool, "target": target, "port": 443, "protocol": "tcp", "service": "https",
        "action_id": action_id, "execution_identity": ACTION_IDENTITIES[action_id],
        "authorization_parameters": parameters,
        "authorization_parameters_hash": parameter_hash(parameters),
    }


def test_batch0_contract_has_versioned_unique_template_and_execution_identity():
    assert set(ACTION_IDENTITIES) == set(ACTION_TEMPLATES)
    assert len(set(ACTION_IDENTITIES.values())) == 2
    assert len(set(ACTION_TEMPLATES.values())) == 2
    assert all(value.endswith("v2") for value in ACTION_IDENTITIES.values())
    assert all(value.endswith("_v2") for value in ACTION_TEMPLATES.values())


def test_header_tool_only_request_fails_closed(monkeypatch):
    monkeypatch.setattr(worker, "resolve_target", lambda target: [target])
    body = TestClient(worker.app).post("/execute", json={
        "tool": "http_security_headers", "target": "192.0.2.20", "port": 443,
    }).json()
    assert body["status"] == "rejected"
    assert "authorization required" in body["reason"]


def test_header_identity_mismatch_fails_closed(monkeypatch):
    monkeypatch.setattr(worker, "resolve_target", lambda target: [target])
    payload = authorized_request("http_security_headers.collect.v1", "http_security_headers")
    payload["execution_identity"] = "builtin:wrong"
    assert TestClient(worker.app).post("/execute", json=payload).json()["status"] == "rejected"


def test_nuclei_canonical_url_substitution_fails_closed(monkeypatch):
    monkeypatch.setattr(worker, "resolve_target", lambda target: [target])
    payload = authorized_request("nuclei.safe_scan.v1", "nuclei_safe")
    payload["authorization_parameters"]["canonical_url"] = "https://192.0.2.99:443/"
    payload["authorization_parameters_hash"] = parameter_hash(payload["authorization_parameters"])
    body = TestClient(worker.app).post("/execute", json=payload).json()
    assert body["status"] == "rejected"
    assert "parameter identity mismatch" in body["reason"]
