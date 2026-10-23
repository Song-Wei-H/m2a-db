from __future__ import annotations

from uuid import uuid4
from pathlib import Path
from unittest.mock import patch

import pytest

from app.action_contracts import ACTION_IDENTITIES, ACTION_TEMPLATES
from app.execution_governance import canonical_parameters, parameter_hash
from kali_worker.app import WORKER_BUILD_SHA256
from worker.remote_runner import run_remote_tool
from worker.tool_runner import TaskContext


ACTION = "http_security_headers.collect.v1"
LEGACY_RUN_ID = "0123456789ab"
LEGACY_OUTPUT = str(Path(__file__).resolve().parents[1] / "experiments" / "gade-seven-level-v1"
                    / "real-worker-l1" / "local-only" / LEGACY_RUN_ID)


def governed_context() -> TaskContext:
    parameters = canonical_parameters(
        target="192.0.2.10", port=18080, protocol="tcp", service="http", action_id=ACTION
    )
    return TaskContext(
        task_id=31,
        target_id=7,
        tool_name="http_security_headers",
        host="192.0.2.10",
        port=18080,
        protocol="tcp",
        service="http",
        open_port_id=9,
        action_id=ACTION,
        execution_identity=ACTION_IDENTITIES[ACTION],
        authorization_parameters=parameters,
        authorization_parameters_hash=parameter_hash(parameters),
        authorization_id=41,
        request_id=str(uuid4()),
        correlation_id=str(uuid4()),
        template_id=ACTION_TEMPLATES[ACTION],
        expected_worker_build_sha256=WORKER_BUILD_SHA256,
    )


class FakeResponse:
    def __init__(self, status_code: int, body: object):
        self.status_code = status_code
        self.body = body
        self.text = "fake response body"
        self.headers = {"date": "Wed, 14 Oct 2026 03:00:01 GMT"}

    def json(self):
        if isinstance(self.body, Exception):
            raise self.body
        return self.body


class FakeClient:
    def __init__(self, response: FakeResponse):
        self.response = response
        self.request = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def post(self, url, json):
        self.request = {"url": url, "json": json}
        return self.response


def receipt_for(payload: dict, *, request_id: str | None = None, outcome: str = "completed",
                action_success: bool = True) -> dict:
    return {
        "request_id": request_id or payload["request_id"],
        "correlation_id": payload["correlation_id"],
        "task_id": payload["task_id"],
        "authorization_id": payload["authorization_id"],
        "template_id": payload["template_id"],
        "request_hash": parameter_hash(payload),
        "executed_action": payload["action_id"],
        "executed_parameters": payload["authorization_parameters"],
        "execution_identity": payload["execution_identity"],
        "worker_replay_claim": "PERSISTED_SINGLE_USE",
        "handler_invoked": True,
        "request_received_at_utc": "2026-10-14T02:12:05.000000Z",
        "handler_started_at_utc": "2026-10-14T02:12:05.100000Z",
        "handler_completed_at_utc": "2026-10-14T02:12:05.200000Z",
        "worker_build_sha256": payload["expected_worker_build_sha256"],
        "execution_outcome": outcome,
        "action_success": action_success,
    }


@pytest.mark.asyncio
async def test_http_200_with_failed_action_is_not_execution_success():
    ctx = governed_context()
    body = {
        "status": "failed",
        "error": "connection refused",
        "command": "builtin:http_security_headers",
        "raw_output": "",
        "parsed_result": {"success": False, "error": "connection refused"},
    }
    # Build the receipt from the exact request payload sent by the runner.
    response = FakeResponse(200, body)
    client = FakeClient(response)
    with patch("worker.remote_runner.httpx.AsyncClient", return_value=client):
        # The first payload is deterministic from this context and can be assembled
        # with the same public request helper used by the production runner.
        from app.execution_trace import execution_request
        body["execution_receipt"] = receipt_for(
            execution_request(ctx), outcome="failed", action_success=False
        )
        result = await run_remote_tool(ctx)

    assert client.request["json"]["request_id"] == ctx.request_id
    assert result.success is False
    assert result.status == "failed"
    assert result.worker_exchange["http_status"] == 200
    assert result.worker_exchange["application_status"] == "failed"
    assert result.worker_exchange["receipt_valid"] is True


@pytest.mark.asyncio
async def test_http_200_without_receipt_is_not_execution_verified():
    ctx = governed_context()
    client = FakeClient(FakeResponse(200, {
        "status": "completed", "command": "builtin:http_security_headers",
        "raw_output": "status code 200", "parsed_result": {"success": True, "status_code": 200},
    }))
    with patch("worker.remote_runner.httpx.AsyncClient", return_value=client):
        result = await run_remote_tool(ctx)

    assert result.success is False
    assert result.error_message == "Worker execution receipt missing"
    assert result.worker_exchange["receipt_present"] is False
    assert result.worker_exchange["receipt_valid"] is False


@pytest.mark.asyncio
async def test_receipt_with_mismatched_request_id_is_rejected():
    ctx = governed_context()
    from app.execution_trace import execution_request
    payload = execution_request(ctx)
    body = {
        "status": "completed", "command": "builtin:http_security_headers", "raw_output": "ok",
        "parsed_result": {"success": True},
        "execution_receipt": receipt_for(payload, request_id=str(uuid4())),
    }
    client = FakeClient(FakeResponse(200, body))
    with patch("worker.remote_runner.httpx.AsyncClient", return_value=client):
        result = await run_remote_tool(ctx)

    assert result.success is False
    assert result.error_message == "Worker authority-to-execution drift"
    assert result.worker_exchange["receipt_valid"] is False


@pytest.mark.asyncio
async def test_receipt_without_persistent_replay_claim_is_rejected():
    ctx = governed_context()
    from app.execution_trace import execution_request
    payload = execution_request(ctx)
    receipt = receipt_for(payload)
    receipt.pop("worker_replay_claim")
    body = {
        "status": "completed", "command": "builtin:http_security_headers", "raw_output": "ok",
        "parsed_result": {"success": True}, "execution_receipt": receipt,
    }
    client = FakeClient(FakeResponse(200, body))
    with patch("worker.remote_runner.httpx.AsyncClient", return_value=client):
        result = await run_remote_tool(ctx)

    assert result.success is False
    assert result.error_message == "Worker authority-to-execution drift"
    assert result.worker_exchange["receipt_valid"] is False


@pytest.mark.asyncio
async def test_http_error_response_is_preserved_as_failed_exchange():
    ctx = governed_context()
    client = FakeClient(FakeResponse(503, {"status": "completed", "raw_output": "not executed"}))
    with patch("worker.remote_runner.httpx.AsyncClient", return_value=client):
        result = await run_remote_tool(ctx)

    assert result.success is False
    assert result.error_message == "Worker returned HTTP 503"
    assert result.worker_exchange["http_status"] == 503
    assert result.worker_exchange["trace_error"] == "Worker returned HTTP 503"


def legacy_response(*, status="completed", success=True, target="10.56.66.119"):
    return {
        "status": status,
        "command": "builtin:http_security_headers",
        "raw_output": '{"method":"HEAD","status_code":200}',
        "parsed_result": {
            "success": success,
            "tool_name": "http_security_headers",
            "host": target,
            "port": 18080,
            "method": "HEAD",
            "status_code": 200,
            "headers": {"server": "nginx"},
        },
    }


def legacy_context() -> TaskContext:
    parameters = canonical_parameters(
        target="10.56.66.119", port=18080, protocol="tcp", service="http", action_id=ACTION
    )
    return TaskContext(
        task_id=31, target_id=7, tool_name="http_security_headers", host="10.56.66.119",
        port=18080, protocol="tcp", service="http", open_port_id=9,
        action_id=ACTION, execution_identity=ACTION_IDENTITIES[ACTION],
        authorization_parameters=parameters, authorization_parameters_hash=parameter_hash(parameters),
        authorization_id=41, request_id=str(uuid4()), correlation_id=str(uuid4()),
        template_id=ACTION_TEMPLATES[ACTION], expected_worker_build_sha256=WORKER_BUILD_SHA256,
    )


@pytest.mark.asyncio
async def test_legacy_adapter_sends_only_fixed_old_api_fields_and_marks_receipt_unavailable(monkeypatch):
    monkeypatch.setenv("M2A_WORKER_API_MODE", "legacy")
    monkeypatch.setenv("GADE_L1_RUN_ID", LEGACY_RUN_ID)
    monkeypatch.setenv("GADE_L1_OUTPUT", LEGACY_OUTPUT)
    ctx = legacy_context()
    client = FakeClient(FakeResponse(200, legacy_response()))
    with patch("worker.remote_runner.httpx.AsyncClient", return_value=client):
        result = await run_remote_tool(ctx)

    sent = client.request["json"]
    assert sent == {
        "tool": "http_security_headers", "target": "10.56.66.119",
        "port": 18080, "service": "http",
    }
    assert "request_id" not in sent and "authorization_id" not in sent
    assert result.success is True
    assert result.execution_receipt is None
    assert result.worker_exchange["native_receipt_status"] == "NATIVE_WORKER_RECEIPT_UNAVAILABLE"
    assert result.worker_exchange["http_request"]["body"] == sent
    assert result.worker_exchange["correlation_id"] == ctx.correlation_id


@pytest.mark.asyncio
async def test_legacy_adapter_rejects_target_or_contract_expansion_before_network(monkeypatch):
    monkeypatch.setenv("M2A_WORKER_API_MODE", "legacy")
    monkeypatch.setenv("GADE_L1_RUN_ID", LEGACY_RUN_ID)
    monkeypatch.setenv("GADE_L1_OUTPUT", LEGACY_OUTPUT)
    ctx = legacy_context()
    drifted = ctx.__class__(**{**ctx.__dict__, "host": "10.56.66.120"})
    with patch("worker.remote_runner.httpx.AsyncClient") as client:
        with pytest.raises(ValueError, match="non-canonical"):
            await run_remote_tool(drifted)
        client.assert_not_called()


@pytest.mark.asyncio
async def test_legacy_adapter_rejects_output_path_outside_run_scoped_allowlist(monkeypatch):
    monkeypatch.setenv("M2A_WORKER_API_MODE", "legacy")
    monkeypatch.setenv("GADE_L1_RUN_ID", LEGACY_RUN_ID)
    monkeypatch.setenv("GADE_L1_OUTPUT", str(Path(__file__).resolve().parents[1]))
    with pytest.raises(ValueError, match="output path"):
        await run_remote_tool(legacy_context())


@pytest.mark.asyncio
async def test_legacy_http_200_with_action_failure_remains_failed(monkeypatch):
    monkeypatch.setenv("M2A_WORKER_API_MODE", "legacy")
    monkeypatch.setenv("GADE_L1_RUN_ID", LEGACY_RUN_ID)
    monkeypatch.setenv("GADE_L1_OUTPUT", LEGACY_OUTPUT)
    client = FakeClient(FakeResponse(200, legacy_response(status="failed", success=False)))
    with patch("worker.remote_runner.httpx.AsyncClient", return_value=client):
        result = await run_remote_tool(legacy_context())

    assert result.success is False
    assert result.status == "failed"
    assert result.execution_receipt is None
    assert result.worker_exchange["native_receipt_status"] == "NATIVE_WORKER_RECEIPT_UNAVAILABLE"


@pytest.mark.asyncio
async def test_legacy_completed_envelope_without_exact_action_output_is_failed(monkeypatch):
    monkeypatch.setenv("M2A_WORKER_API_MODE", "legacy")
    monkeypatch.setenv("GADE_L1_RUN_ID", LEGACY_RUN_ID)
    monkeypatch.setenv("GADE_L1_OUTPUT", LEGACY_OUTPUT)
    client = FakeClient(FakeResponse(200, legacy_response(target="10.56.66.120")))
    with patch("worker.remote_runner.httpx.AsyncClient", return_value=client):
        result = await run_remote_tool(legacy_context())

    assert result.success is False
    assert result.worker_exchange["legacy_result_fields_valid"] is False
