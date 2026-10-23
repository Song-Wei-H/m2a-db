import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.action_contracts import (
    ACTION_PARAMETER_SCHEMAS,
    ACTION_BY_TOOL,
    ACTION_IDENTITIES,
    ACTION_REQUIRED_ATTACK_DEPTH,
    ACTION_TEMPLATES,
    canonical_action_parameters,
)
from app.attack_authorization import depth_decision
from app.execution_governance import parameter_hash
from app.config import settings
from app.security.tool_policy import resolve_template_tool
from kali_worker import app as worker


ACTION = "lab.valid_account_access.v1"
TOOL = "lab_valid_account_access"
TARGET = "10.56.66.119"
PORT = 18080


@pytest.fixture(autouse=True)
def worker_replay_ledger(monkeypatch, tmp_path):
    monkeypatch.setenv("KALI_WORKER_REPLAY_DB_PATH", str(tmp_path / "worker-replay.sqlite3"))


def make_request(**overrides):
    correlation_id = overrides.pop("correlation_id", f"GADE-L2-{uuid4()}")
    parameters = canonical_action_parameters(
        action_id=ACTION, target=TARGET, port=PORT, protocol="tcp", service="http"
    )
    request = {
        "tool": TOOL,
        "target": TARGET,
        "port": PORT,
        "protocol": "tcp",
        "service": "http",
        "action_id": ACTION,
        "execution_identity": ACTION_IDENTITIES[ACTION],
        "authorization_parameters": parameters,
        "authorization_parameters_hash": parameter_hash(parameters),
        "task_id": 42,
        "authorization_id": 7,
        "request_id": str(uuid4()),
        "correlation_id": correlation_id,
        "template_id": ACTION_TEMPLATES[ACTION],
        "expected_worker_build_sha256": worker.WORKER_BUILD_SHA256,
    }
    request.update(overrides)
    return request


def test_l2_contract_is_fixed_to_lab_and_maps_to_depth_2():
    assert ACTION_BY_TOOL[TOOL] == ACTION
    assert ACTION_REQUIRED_ATTACK_DEPTH[ACTION] == 2
    params = canonical_action_parameters(
        action_id=ACTION, target=TARGET, port=PORT, protocol="tcp", service="http"
    )
    assert params["login_path"] == "/lab/auth/login"
    assert params["protected_path"] == "/lab/protected"
    assert "password" not in params and "username" not in params
    assert depth_decision(7, 2)["passed"] is True
    assert depth_decision(1, 2)["reason_code"] == "ATTACK_DEPTH_EXCEEDED"
    assert "password" not in json.dumps(ACTION_PARAMETER_SCHEMAS[ACTION])
    with pytest.raises(ValueError, match="fixed to the authorized Lab"):
        canonical_action_parameters(
            action_id=ACTION, target="10.56.66.120", port=PORT,
            protocol="tcp", service="http",
        )


def test_l2_tool_is_only_allowed_when_experiment_allowlist_explicitly_enables_it(monkeypatch):
    monkeypatch.setattr(settings, "allowed_tools", "http_security_headers")
    with pytest.raises(ValueError, match="not in ALLOWED_TOOLS"):
        resolve_template_tool(TOOL)
    monkeypatch.setattr(settings, "allowed_tools", f"http_security_headers,{TOOL}")
    assert resolve_template_tool(TOOL) == TOOL


def test_l2_action_is_not_exposed_by_shared_worker_profile(monkeypatch):
    monkeypatch.setenv("KALI_WORKER_PROFILE", "shared")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_TOOLS", "")
    assert TOOL not in worker.effective_allowed_tools()
    response = TestClient(worker.app).post("/execute", json=make_request())
    assert response.json() == {"status": "rejected", "reason": "tool not allowed", "tool": TOOL}


def test_gade_l2_handler_performs_fixed_login_and_protected_access_without_leaking_secrets(monkeypatch, caplog):
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", f"{TARGET}/32")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_TOOLS", TOOL)
    username = "lab-user-only"
    password = "unit-test-password-that-is-not-real-0001"
    token = "unit-test-session-token-never-persist-this-value-0001"
    monkeypatch.setenv("GADE_L2_TEST_USERNAME", username)
    monkeypatch.setenv("GADE_L2_TEST_PASSWORD", password)
    case_id = f"GADE-L2-{uuid4()}"
    calls = []

    class Response:
        def __init__(self, status, body):
            self.status = status
            self._body = body

        def read(self, _limit):
            return self._body

    class FakeConnection:
        def __init__(self, host, port, timeout):
            assert (host, port, timeout) == (TARGET, PORT, 8)
            self.method = None
            self.path = None
            self.headers = None

        def request(self, method, path, body=None, headers=None):
            self.method, self.path, self.headers = method, path, headers or {}
            calls.append({"method": method, "path": path, "headers": self.headers, "body": body})

        def getresponse(self):
            if self.path == "/lab/auth/login":
                body = json.loads(calls[-1]["body"])
                assert body == {"username": username, "password": password}
                return Response(200, json.dumps({"session_token": token, "expires_in": 60,
                                                 "test_case_id": case_id}).encode())
            assert self.path == "/lab/protected"
            assert self.headers.get("Authorization") == f"Bearer {token}"
            return Response(200, json.dumps({"resource": "lab-only-protected-resource",
                "scenario": "T1078-test-account", "access": "granted",
                "test_case_id": case_id}).encode())

        def close(self):
            pass

    monkeypatch.setattr(worker.http.client, "HTTPConnection", FakeConnection)
    payload = make_request(correlation_id=case_id)
    response = TestClient(worker.app).post("/execute", json=payload)
    body = response.json()
    assert response.status_code == 200
    assert body["status"] == "completed"
    assert body["parsed_result"]["success"] is True
    assert body["parsed_result"]["login_http_status"] == 200
    assert body["parsed_result"]["protected_http_status"] == 200
    assert [call["path"] for call in calls] == ["/lab/auth/login", "/lab/protected"]
    assert calls[0]["headers"]["X-Request-ID"] == payload["request_id"]
    assert calls[0]["headers"]["X-Test-Case-ID"] == case_id
    receipt = body["execution_receipt"]
    assert receipt["executed_action"] == ACTION
    assert receipt["action_success"] is True
    rendered = json.dumps(body)
    assert password not in rendered and username not in rendered and token not in rendered
    assert password not in caplog.text and token not in caplog.text


def test_l2_handler_fails_closed_without_worker_local_credentials(monkeypatch):
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", f"{TARGET}/32")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_TOOLS", TOOL)
    monkeypatch.delenv("GADE_L2_TEST_USERNAME", raising=False)
    monkeypatch.delenv("GADE_L2_TEST_PASSWORD", raising=False)
    monkeypatch.setattr(worker.http.client, "HTTPConnection", lambda *args, **kwargs: pytest.fail("must not connect"))
    response = TestClient(worker.app).post("/execute", json=make_request())
    assert response.json()["status"] == "failed"
    assert response.json()["parsed_result"]["error"] == "worker-local test credentials unavailable"


def test_l2_worker_rejects_noncanonical_target_before_handler(monkeypatch):
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", "10.56.66.0/24")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_TOOLS", TOOL)
    monkeypatch.setattr(worker, "run_lab_valid_account_access", lambda *_: pytest.fail("handler must not run"))
    payload = make_request(target="10.56.66.120")
    response = TestClient(worker.app).post("/execute", json=payload)
    assert response.json()["status"] == "rejected"
