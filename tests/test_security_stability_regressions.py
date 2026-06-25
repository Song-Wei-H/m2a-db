import importlib
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.config import settings
from app.models import ToolRequest
from app.security.scope import target_in_allowed_scope
from app.tool_catalog import CANONICAL_ALLOWED_TOOLS, MITRE_ALLOWED_TOOL_IDS, default_allowed_tools_value


class FakeScalarResult:
    def __init__(self, value=None):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class FakeAsyncBegin:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


def test_import_tool_policy_does_not_write_stdout(capsys):
    import app.security.tool_policy as tool_policy

    importlib.reload(tool_policy)

    captured = capsys.readouterr()
    assert captured.out == ""


@pytest.mark.asyncio
async def test_tool_request_creation_uses_model_fields_without_type_error():
    from app.tool_task_dispatcher import dispatch_llm_tool_proposal

    target = SimpleNamespace(id=7, target="192.0.2.20", scope="internal")
    db = MagicMock()
    db.execute = AsyncMock(side_effect=[FakeScalarResult(target), FakeScalarResult(None)])
    db.add = MagicMock()
    db.flush = AsyncMock()

    result = await dispatch_llm_tool_proposal(
        db,
        {
            "tool": "dirb_safe",
            "target": "192.0.2.20",
            "reason": "Directory validation requested",
            "risk_level": "medium",
        },
        profile="internal",
        target_id=7,
    )

    assert result.status == "pending_tool_request"
    request = db.add.call_args.args[0]
    assert isinstance(request, ToolRequest)
    assert request.requested_tool == "dirb_safe"
    assert request.requested_capability == "tool_execution"
    assert request.status == "pending_review"
    assert request.reasoning_json["requested_by"] == "llm"
    assert request.reasoning_json["reason"] == "Tool not registered"


@pytest.mark.asyncio
async def test_decision_engine_resolve_template_tool_failure_does_not_name_error():
    from app.decision_engine import run_decision_for_target

    db = MagicMock()
    db.begin = MagicMock(return_value=FakeAsyncBegin())
    db.get = AsyncMock(return_value=SimpleNamespace(id=1))
    db.execute = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()

    with patch("app.decision_engine._load_assessment_context", AsyncMock(return_value=SimpleNamespace(
        target_id=1,
        open_ports=[],
        vulnerabilities=[],
        tool_results=[],
    ))), patch("app.decision_engine.compute_risk_score", return_value=5.0), patch(
        "app.decision_engine.compute_confidence", return_value=0.9
    ), patch("app.decision_engine.pick_focus_port", return_value=None), patch(
        "app.decision_engine.select_next_tool",
        return_value=SimpleNamespace(tool="unsupported_tool", rationale="test"),
    ), patch("app.decision_engine.decide_next_action", return_value="continue"), patch(
        "app.decision_engine.resolve_template_tool", side_effect=ValueError("unsupported")
    ):
        result = await run_decision_for_target(db, 1)

    assert result.tool_task_id is None
    assert result.next_tool == "unsupported_tool"


def test_allowed_tool_sources_are_consistent(monkeypatch):
    from app.mitre_rules import ALLOWED_TOOLS
    from app.security.tool_policy import LLM_ALLOWED_TOOLS, resolve_template_tool

    monkeypatch.setattr(settings, "allowed_tools", default_allowed_tools_value())

    assert LLM_ALLOWED_TOOLS == CANONICAL_ALLOWED_TOOLS
    assert set(settings.allowed_tools_list) == set(CANONICAL_ALLOWED_TOOLS)
    assert ALLOWED_TOOLS == MITRE_ALLOWED_TOOL_IDS
    for tool in CANONICAL_ALLOWED_TOOLS:
        assert resolve_template_tool(tool) == tool


def test_hostname_scope_allowlist_and_denylist(monkeypatch):
    monkeypatch.setattr(settings, "allowed_hostnames", "app.example.test")
    monkeypatch.setattr(settings, "allowed_domain_suffixes", "internal.example")

    assert target_in_allowed_scope("app.example.test") is True
    assert target_in_allowed_scope("scan.internal.example") is True
    assert target_in_allowed_scope("internal.example") is True
    assert target_in_allowed_scope("evil.example.test") is False
    assert target_in_allowed_scope("example.com") is False


def test_ip_scope_still_uses_cidr(monkeypatch):
    monkeypatch.setattr(settings, "allowed_scopes", "192.0.2.0/24")
    monkeypatch.setattr(settings, "allowed_hostnames", "")
    monkeypatch.setattr(settings, "allowed_domain_suffixes", "")

    assert target_in_allowed_scope("192.0.2.42") is True
    assert target_in_allowed_scope("198.51.100.42") is False
