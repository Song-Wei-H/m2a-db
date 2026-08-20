from fastapi.testclient import TestClient

from app.action_contracts import ACTION_IDENTITIES, canonical_action_parameters
from app.execution_governance import parameter_hash
from kali_worker import app as worker


def payload(action_id: str, tool: str, *, target: str, port: int | None,
            protocol: str | None, service: str | None) -> dict:
    parameters = canonical_action_parameters(
        action_id=action_id, target=target, port=port, protocol=protocol, service=service,
    )
    return {
        "tool": tool, "target": target, "port": port, "protocol": protocol,
        "service": service, "action_id": action_id,
        "execution_identity": ACTION_IDENTITIES[action_id],
        "authorization_parameters": parameters,
        "authorization_parameters_hash": parameter_hash(parameters),
    }


def execute(body: dict, monkeypatch) -> dict:
    monkeypatch.setattr(worker, "resolve_target", lambda target: ["192.0.2.30"])
    monkeypatch.setattr(worker, "run_dns_metadata", lambda target, addresses: {
        "status": "completed", "parsed_result": {"host": target}, "raw_output": ""
    })
    monkeypatch.setattr(worker, "run_tls_certificate", lambda target, port, sni=None: {
        "status": "completed", "parsed_result": {"host": target, "port": port, "sni": sni},
        "raw_output": "",
    })
    return TestClient(worker.app).post("/execute", json=body).json()


def test_dns_and_tls_without_authorization_fail_closed(monkeypatch):
    monkeypatch.setattr(worker, "resolve_target", lambda target: [target])
    for tool in ("dns_metadata", "tls_certificate"):
        body = TestClient(worker.app).post("/execute", json={"tool": tool, "target": "asset.example"}).json()
        assert body["status"] == "rejected"
        assert "authorization required" in body["reason"]


def test_dns_authorized_contract_executes(monkeypatch):
    body = payload("dns.metadata_collect.v1", "dns_metadata", target="Asset.Example.",
                   port=None, protocol=None, service="dns")
    assert body["authorization_parameters"]["normalized_hostname"] == "asset.example"
    assert execute(body, monkeypatch)["status"] == "completed"


def test_dns_target_domain_parameter_and_identity_substitution_blocked(monkeypatch):
    original = payload("dns.metadata_collect.v1", "dns_metadata", target="a.example",
                       port=None, protocol=None, service="dns")
    variants = []
    for key, value in (("target", "b.example"), ("service", "other")):
        changed = {**original, key: value}
        variants.append(changed)
    drift = {**original, "execution_identity": "builtin:dns-metadata:drift"}
    variants.append(drift)
    for changed in variants:
        assert execute(changed, monkeypatch)["status"] == "rejected"


def test_tls_authorized_host_port_and_sni_are_worker_values(monkeypatch):
    body = payload("tls.certificate_collect.v1", "tls_certificate", target="tls.example",
                   port=8443, protocol="tcp", service="tls")
    result = execute(body, monkeypatch)
    assert result["status"] == "completed"
    assert result["parsed_result"] == {"host": "tls.example", "port": 8443, "sni": "tls.example"}


def test_tls_target_port_sni_parameter_and_identity_substitution_blocked(monkeypatch):
    original = payload("tls.certificate_collect.v1", "tls_certificate", target="tls.example",
                       port=443, protocol="tcp", service="tls")
    variants = [{**original, "target": "other.example"}, {**original, "port": 444}]
    sni = {**original, "authorization_parameters": {**original["authorization_parameters"], "sni": "other.example"}}
    sni["authorization_parameters_hash"] = parameter_hash(sni["authorization_parameters"])
    variants.extend([sni, {**original, "execution_identity": "builtin:tls:drift"}])
    for changed in variants:
        assert execute(changed, monkeypatch)["status"] == "rejected"
