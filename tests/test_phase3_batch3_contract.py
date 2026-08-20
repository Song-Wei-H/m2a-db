from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from app.action_contracts import ACTION_BY_TOOL, ACTION_IDENTITIES, canonical_action_parameters
from app.execution_governance import parameter_hash, utcnow_naive
from kali_worker import app as worker
from worker.task_poller import _claim_task


def authorized_httpx(*, target="web.example", port=80, service="http") -> dict:
    action_id = "httpx.web_probe.v1"
    parameters = canonical_action_parameters(
        action_id=action_id, target=target, port=port, protocol="tcp", service=service,
    )
    return {
        "tool": "httpx_basic", "target": target, "port": port,
        "protocol": "tcp", "service": service, "action_id": action_id,
        "execution_identity": ACTION_IDENTITIES[action_id],
        "authorization_parameters": parameters,
        "authorization_parameters_hash": parameter_hash(parameters),
    }


def test_httpx_without_authorization_fails_closed(monkeypatch):
    monkeypatch.setattr(worker, "resolve_target", lambda target: [target])
    body = TestClient(worker.app).post("/execute", json={
        "tool": "httpx_basic", "target": "web.example", "port": 80,
    }).json()
    assert body["status"] == "rejected"
    assert "authorization required" in body["reason"]


def test_httpx_exact_authorized_root_probe_has_no_redirect_flag(monkeypatch):
    monkeypatch.setattr(worker, "resolve_target", lambda target: [target])
    monkeypatch.setattr(worker, "run_command", lambda argv: {
        "status": "completed", "command": " ".join(argv), "raw_output": "",
    })
    body = TestClient(worker.app).post("/execute", json=authorized_httpx()).json()
    assert body["status"] == "completed"
    assert body["command"].split() == [
        "httpx", "-u", "http://web.example:80/", "-json", "-title",
        "-tech-detect", "-status-code",
    ]
    assert "redirect" not in body["command"]


def test_httpx_target_scheme_port_url_path_flag_and_identity_substitution_blocked(monkeypatch):
    monkeypatch.setattr(worker, "resolve_target", lambda target: [target])
    original = authorized_httpx()
    changes = [
        {**original, "target": "other.example"},
        {**original, "service": "https", "port": 443},
        {**original, "port": 8080},
    ]
    for field, value in (
        ("canonical_url", "http://web.example:80/admin"),
        ("path", "/admin"),
        ("redirect_policy", {"follow": True, "max_redirects": 10, "cross_host": True}),
        ("argv", ["httpx", "-u", "http://other.example:80/", "-follow-redirects"]),
    ):
        params = {**original["authorization_parameters"], field: value}
        changes.append({**original, "authorization_parameters": params,
                        "authorization_parameters_hash": parameter_hash(params)})
    changes.append({**original, "execution_identity": "argv:httpx:drift"})
    for body in changes:
        assert TestClient(worker.app).post("/execute", json=body).json()["status"] == "rejected"


@pytest.mark.asyncio
@pytest.mark.parametrize("expired,consumed", [(True, 0), (False, 1)])
async def test_httpx_expired_or_replayed_authorization_cannot_claim(expired, consumed):
    task = SimpleNamespace(
        id=40, target_id=7, status="pending", approval_status="not_required",
        tool_name="httpx_basic", execution_authorization_id=41,
        action_id="httpx.web_probe.v1",
    )
    authorization = SimpleNamespace(
        target_id=7, action_id=task.action_id,
        expires_at=utcnow_naive() + timedelta(seconds=-1 if expired else 60),
        consumed_count=consumed, execution_limit=1,
    )
    db = MagicMock()
    db.get = AsyncMock(side_effect=[task, authorization])
    assert await _claim_task(db, task.id) is False


def test_post_httpx_migrated_downstream_paths_use_shared_governance():
    analysis = Path("worker/analysis_pipeline.py").read_text(encoding="utf-8")
    auto = Path("worker/task_generator.py").read_text(encoding="utf-8")
    writer = Path("app/tool_task_writer.py").read_text(encoding="utf-8")
    assert "create_tool_task_if_not_exists" in analysis
    assert "propose_and_authorize" in auto
    assert "_adapt_migrated_action" in writer
    assert ACTION_BY_TOOL["http_security_headers"] == "http_security_headers.collect.v1"
    assert ACTION_BY_TOOL["nuclei_safe"] == "nuclei.safe_scan.v1"
