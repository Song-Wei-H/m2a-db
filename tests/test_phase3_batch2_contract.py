from pathlib import Path
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from app.action_contracts import ACTION_BY_TOOL, ACTION_IDENTITIES, canonical_action_parameters
from app.execution_governance import parameter_hash, utcnow_naive
from kali_worker import app as worker
from worker.task_poller import _claim_task


def authorized_nmap(target: str = "192.0.2.40") -> dict:
    action_id = "nmap.service_fingerprint.v1"
    parameters = canonical_action_parameters(
        action_id=action_id, target=target, port=None, protocol=None, service=None,
    )
    return {
        "tool": "nmap_service", "target": target, "action_id": action_id,
        "execution_identity": ACTION_IDENTITIES[action_id],
        "authorization_parameters": parameters,
        "authorization_parameters_hash": parameter_hash(parameters),
    }


def test_nmap_without_authorization_fails_closed(monkeypatch):
    monkeypatch.setattr(worker, "resolve_target", lambda target: [target])
    body = TestClient(worker.app).post("/execute", json={
        "tool": "nmap_service", "target": "192.0.2.40",
    }).json()
    assert body["status"] == "rejected"
    assert "authorization required" in body["reason"]


def test_nmap_executes_only_exact_authorized_argv(monkeypatch):
    captured = {}
    monkeypatch.setattr(worker, "resolve_target", lambda target: [target])
    monkeypatch.setattr(worker, "run_command", lambda argv: captured.setdefault("result", {
        "status": "completed", "command": " ".join(argv), "raw_output": "",
    }))
    body = TestClient(worker.app).post("/execute", json=authorized_nmap()).json()
    assert body["status"] == "completed"
    assert body["command"].split() == ["nmap", "-sV", "192.0.2.40"]


def test_nmap_target_port_scope_parameter_and_identity_substitution_blocked(monkeypatch):
    monkeypatch.setattr(worker, "resolve_target", lambda target: [target])
    original = authorized_nmap()
    changed_scope = {
        **original,
        "authorization_parameters": {
            **original["authorization_parameters"], "port_scope": "1-65535",
        },
    }
    changed_scope["authorization_parameters_hash"] = parameter_hash(changed_scope["authorization_parameters"])
    variants = [
        {**original, "target": "192.0.2.41"},
        {**original, "port": 443},
        changed_scope,
        {**original, "execution_identity": "argv:nmap:-sV:-p-:drift"},
    ]
    for body in variants:
        assert TestClient(worker.app).post("/execute", json=body).json()["status"] == "rejected"


def test_post_nmap_paths_cannot_bypass_migrated_action_governance():
    analysis_source = Path("worker/analysis_pipeline.py").read_text(encoding="utf-8")
    auto_source = Path("worker/task_generator.py").read_text(encoding="utf-8")
    writer_source = Path("app/tool_task_writer.py").read_text(encoding="utf-8")
    assert "create_tool_task_if_not_exists" in analysis_source
    assert "propose_and_authorize" in auto_source
    assert "_adapt_migrated_action" in writer_source
    assert ACTION_BY_TOOL["http_security_headers"] == "http_security_headers.collect.v1"
    assert ACTION_BY_TOOL["nuclei_safe"] == "nuclei.safe_scan.v1"


@pytest.mark.asyncio
@pytest.mark.parametrize("expired,consumed", [(True, 0), (False, 1)])
async def test_nmap_expired_or_consumed_authorization_cannot_claim(expired, consumed):
    task = SimpleNamespace(
        id=30, target_id=7, status="pending", approval_status="not_required",
        tool_name="nmap_service", execution_authorization_id=31,
        action_id="nmap.service_fingerprint.v1",
    )
    authorization = SimpleNamespace(
        target_id=7, action_id=task.action_id,
        expires_at=utcnow_naive() + timedelta(seconds=-1 if expired else 60),
        consumed_count=consumed, execution_limit=1,
    )
    db = MagicMock()
    db.get = AsyncMock(side_effect=[task, authorization])
    assert await _claim_task(db, task.id) is False
