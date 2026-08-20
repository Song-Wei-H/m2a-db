from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from app.action_contracts import ACTION_BY_TOOL, ACTION_IDENTITIES, canonical_action_parameters
from app.execution_governance import parameter_hash, utcnow_naive
from kali_worker import app as worker
from worker.analysis_pipeline import _score_open_port
from worker.task_poller import _claim_task


ACTION_CASES = (
    ("ssh-enum", "ssh.algorithms_enum.v1", 22, "ssh", "ssh2-enum-algos"),
    ("mysql-info", "mysql.server_info.v1", 3306, "mysql", "mysql-info"),
)


def authorized_request(tool, action_id, port, service):
    parameters = canonical_action_parameters(
        action_id=action_id, target="service.example", port=port,
        protocol="tcp", service=service,
    )
    return {
        "tool": tool, "target": "service.example", "port": port,
        "protocol": "tcp", "service": service, "action_id": action_id,
        "execution_identity": ACTION_IDENTITIES[action_id],
        "authorization_parameters": parameters,
        "authorization_parameters_hash": parameter_hash(parameters),
    }


@pytest.mark.parametrize("tool,action_id,port,service,script", ACTION_CASES)
def test_worker_requires_authorization_and_executes_exact_bounded_argv(
    monkeypatch, tool, action_id, port, service, script,
):
    monkeypatch.setattr(worker, "resolve_target", lambda target: [target])
    client = TestClient(worker.app)
    rejected = client.post("/execute", json={
        "tool": tool, "target": "service.example", "port": port,
        "protocol": "tcp", "service": service,
    }).json()
    assert rejected["status"] == "rejected"
    assert "authorization required" in rejected["reason"]

    monkeypatch.setattr(worker, "run_command", lambda argv: {
        "status": "completed", "command": " ".join(argv), "raw_output": "",
    })
    completed = client.post(
        "/execute", json=authorized_request(tool, action_id, port, service)
    ).json()
    assert completed["command"].split() == [
        "nmap", "--script", script, "-p", str(port), "service.example",
    ]


@pytest.mark.parametrize("tool,action_id,port,service,script", ACTION_CASES)
def test_target_port_script_argv_template_and_identity_drift_fail_closed(
    monkeypatch, tool, action_id, port, service, script,
):
    monkeypatch.setattr(worker, "resolve_target", lambda target: [target])
    original = authorized_request(tool, action_id, port, service)
    changes = [
        {**original, "target": "other.example"},
        {**original, "port": port + 1},
        {**original, "execution_identity": "argv:nmap:drift"},
    ]
    for field, value in (
        ("script", "other-script"),
        ("scripts", [script, "extra-script"]),
        ("argv", ["nmap", "--script", "other-script", "-p", str(port), "service.example"]),
    ):
        parameters = {**original["authorization_parameters"], field: value}
        changes.append({
            **original,
            "authorization_parameters": parameters,
            "authorization_parameters_hash": parameter_hash(parameters),
        })
    for body in changes:
        response = TestClient(worker.app).post("/execute", json=body).json()
        assert response["status"] == "rejected"


def test_mysql_auth_and_credential_injection_is_forbidden_by_request_schema():
    body = authorized_request("mysql-info", "mysql.server_info.v1", 3306, "mysql")
    for field in ("username", "password", "script_args"):
        response = TestClient(worker.app).post(
            "/execute", json={**body, field: "injected"}
        )
        assert response.status_code == 422


def test_service_to_action_applicability_rejects_cross_service_proposals():
    with pytest.raises(ValueError, match="not applicable"):
        canonical_action_parameters(
            action_id="mysql.server_info.v1", target="service.example",
            port=22, protocol="tcp", service="ssh",
        )
    with pytest.raises(ValueError, match="not applicable"):
        canonical_action_parameters(
            action_id="ssh.algorithms_enum.v1", target="service.example",
            port=3306, protocol="tcp", service="mysql",
        )


def test_nmap_service_evidence_selects_only_applicable_registered_action():
    ssh = _score_open_port(SimpleNamespace(service="ssh", port=2222, protocol="tcp"))
    mysql = _score_open_port(SimpleNamespace(service="mysql", port=3307, protocol="tcp"))
    assert ACTION_BY_TOOL[ssh["next_tool"]] == "ssh.algorithms_enum.v1"
    assert ACTION_BY_TOOL[mysql["next_tool"]] == "mysql.server_info.v1"


@pytest.mark.asyncio
@pytest.mark.parametrize("tool,action_id,port,service,script", ACTION_CASES)
@pytest.mark.parametrize("expired,consumed", [(True, 0), (False, 1)])
async def test_expired_or_replayed_authorization_cannot_claim(
    tool, action_id, port, service, script, expired, consumed,
):
    task = SimpleNamespace(
        id=70, target_id=7, status="pending", approval_status="not_required",
        tool_name=tool, execution_authorization_id=71, action_id=action_id,
    )
    authorization = SimpleNamespace(
        target_id=7, action_id=action_id,
        expires_at=utcnow_naive() + timedelta(seconds=-1 if expired else 60),
        consumed_count=consumed, execution_limit=1,
    )
    db = MagicMock()
    db.get = AsyncMock(side_effect=[task, authorization])
    assert await _claim_task(db, task.id) is False


def test_legacy_auto_loop_and_llm_paths_converge_on_shared_governance():
    writer = open("app/tool_task_writer.py", encoding="utf-8").read()
    auto = open("worker/task_generator.py", encoding="utf-8").read()
    llm = open("worker/llm_task_generator.py", encoding="utf-8").read()
    assert "_adapt_migrated_action" in writer
    assert "propose_and_authorize" in auto
    assert "create_tool_task_if_not_exists" in llm
    assert ACTION_BY_TOOL["ssh-enum"] == "ssh.algorithms_enum.v1"
    assert ACTION_BY_TOOL["mysql-info"] == "mysql.server_info.v1"
