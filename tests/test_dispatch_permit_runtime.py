"""Offline integration tests for the production dispatcher/Worker permit seam.

The production functions execute in-process with Fake DB/Clock/Verifier and a
stubbed effect handler. These tests do not establish PostgreSQL or Live safety.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import httpx
import pytest

from app.config import settings
from app.action_contracts import ACTION_IDENTITIES, ACTION_TEMPLATES
from app.dispatch_permit import canonical_binding_sha256, dispatch_permit_required
from app.execution_governance import canonical_parameters, parameter_hash
from app.execution_trace import execution_request
from kali_worker.build_info import worker_build_sha256
from worker import task_poller
from worker.task_poller import execute_task
from worker.tool_runner import TaskContext, ToolRunOutcome


class ImmediateAwaitBlocked(RuntimeError):
    pass


def run_immediate(coro):
    while True:
        try:
            yielded = coro.send(None)
        except StopIteration as done:
            return done.value
        if yielded is not None:
            coro.close()
            raise ImmediateAwaitBlocked(f"unexpected await boundary: {type(yielded).__name__}")


@dataclass
class FakeClock:
    current: datetime

    def now(self) -> datetime:
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)

    def aware(self) -> datetime:
        return self.current.replace(tzinfo=timezone.utc)


class Scalar:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class SessionContext:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeDB:
    def __init__(self, task, auth, target, port, registry, template):
        self.task, self.auth, self.target, self.port = task, auth, target, port
        self.registry, self.template = registry, template
        self.execute_count = 0
        self.begin = MagicMock(side_effect=lambda: SessionContext(self))
        self.execute = AsyncMock(side_effect=self._execute)

    async def _execute(self, _statement):
        index = self.execute_count
        self.execute_count += 1
        if index == 0:  # _claim_task status update
            self.task.status = "running"
            return Scalar(self.task.id)
        if index == 1:  # Target status update
            self.target.status = "running"
            return Scalar(None)
        if index == 2:  # ToolRegistry SELECT
            return Scalar(self.registry)
        if index == 3:  # CommandTemplate SELECT
            return Scalar(self.template)
        raise AssertionError(f"unexpected database call {index}")

    async def get(self, model, _row_id, **_kwargs):
        return {
            "ToolTask": self.task,
            "ExecutionAuthorization": self.auth,
            "Target": self.target,
            "OpenPort": self.port,
        }.get(model.__name__)


class FakeAuthority:
    def __init__(self, task, auth, target, clock):
        self.task, self.auth, self.target, self.clock = task, auth, target, clock
        self.permits: dict[str, dict] = {}
        self.issue_calls = 0
        self.consume_calls = 0
        self.before_consume = None

    def _deny_reason(self, binding):
        if self.target.scope != binding["target_scope"]:
            return "TARGET_SCOPE_REVOKED"
        if self.target.authorization_epoch != binding["target_scope_epoch"]:
            return "TARGET_SCOPE_EPOCH_CHANGED"
        if self.auth.scope != binding["grant_scope"]:
            return "GRANT_SCOPE_CHANGED"
        if self.auth.target_authorization_epoch != binding["grant_scope_epoch"]:
            return "GRANT_SCOPE_EPOCH_CHANGED"
        if self.auth.expires_at <= self.clock.now():
            return "GRANT_EXPIRED"
        if binding["approval_required"]:
            if self.task.approval_status != "approved":
                return "APPROVAL_REVOKED"
            if self.task.approval_epoch != binding["approval_epoch"]:
                return "APPROVAL_EPOCH_CHANGED"
            if self.auth.approval_epoch != binding["grant_approval_epoch"]:
                return "GRANT_APPROVAL_EPOCH_CHANGED"
        return None

    async def issue_permit(self, binding):
        self.issue_calls += 1
        reason = self._deny_reason(binding)
        if reason:
            return {"decision": "DENY", "reason_code": reason}
        permit_id = str(uuid4())
        expires_at = min(self.clock.now() + timedelta(seconds=10), self.auth.expires_at)
        expiry_text = expires_at.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        digest = canonical_binding_sha256(binding)
        self.permits[permit_id] = {
            "binding": dict(binding), "binding_sha256": digest,
            "expires_at": expires_at, "consumed": False,
        }
        return {"decision": "ALLOW", "permit_id": permit_id,
                "expires_at": expiry_text, "binding_sha256": digest}

    def consume_permit(self, permit_id, binding):
        self.consume_calls += 1
        if self.before_consume:
            self.before_consume()
        permit = self.permits.get(permit_id)
        if permit is None or permit["consumed"]:
            return {"decision": "DENY", "reason_code": "PERMIT_REPLAY_OR_UNKNOWN"}
        if permit["binding"] != binding or permit["binding_sha256"] != canonical_binding_sha256(binding):
            return {"decision": "DENY", "reason_code": "PERMIT_BINDING_MISMATCH"}
        now = self.clock.now()
        if permit["expires_at"] <= now or self.auth.expires_at <= now:
            return {"decision": "DENY", "reason_code": "PERMIT_OR_GRANT_EXPIRED"}
        reason = self._deny_reason(binding)
        if reason:
            return {"decision": "DENY", "reason_code": reason}
        permit["consumed"] = True
        return {"decision": "ALLOW", "state": "IN_FLIGHT", "admission_id": str(uuid4())}


def _fixture(clock, *, approval_required=False):
    action_id = "httpx.web_probe.v1"
    target = SimpleNamespace(id=14, target="127.0.0.1", scope="127.0.0.1/32",
                             authorization_epoch=8, status="pending")
    port = SimpleNamespace(id=17, port=18080, protocol="tcp", service="http")
    params = canonical_parameters(target=target.target, port=port.port,
                                  protocol=port.protocol, service=port.service,
                                  action_id=action_id)
    task = SimpleNamespace(
        id=86, target_id=target.id, open_port_id=port.id, decision_score_id=52,
        tool_name="httpx_basic", status="pending", approval_required=approval_required,
        approval_status="approved" if approval_required else "not_required",
        approval_epoch=12 if approval_required else None,
        execution_authorization_id=777, investigation_id="runtime-permit-offline",
        action_id=action_id, execution_audit={}, execution_request=None,
        execution_request_hash=None,
    )
    auth = SimpleNamespace(
        id=777, target_id=target.id, action_id=action_id,
        expires_at=clock.now() + timedelta(minutes=5), consumed_count=0,
        execution_limit=1, scope=target.scope, canonical_parameters=params,
        parameters_hash=parameter_hash(params),
        execution_identity=ACTION_IDENTITIES[action_id], template_version=ACTION_TEMPLATES[action_id],
        validation_tier=1, target_authorization_epoch=8,
        approval_epoch=12 if approval_required else None,
    )
    registry = SimpleNamespace(enabled=True)
    template = SimpleNamespace(enabled=True, template_id=auth.template_version)
    return task, auth, target, port, registry, template


def _configure(monkeypatch, tmp_path, clock, task, auth, target, registry, template,
               *, m2a_verifier, worker_verifier, mutation=None, mutation_at_worker=None,
               replay_calls=1, receipt_loss=False,
               m2a_policy_enabled=True, worker_policy_enabled=True):
    import kali_worker.app as worker_app

    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", "127.0.0.1/32")
    monkeypatch.setenv("KALI_WORKER_REPLAY_DB_PATH", str(tmp_path / "permit-replay.sqlite3"))
    monkeypatch.setattr(settings, "enforce_target_scope", True)
    monkeypatch.setattr(settings, "allowed_scopes", "127.0.0.1/32")
    monkeypatch.setattr(settings, "dispatch_permit_required_actions", "httpx.web_probe.v1")
    monkeypatch.setattr(
        task_poller,
        "dispatch_permit_required",
        lambda action_id: m2a_policy_enabled and action_id == "httpx.web_probe.v1",
    )
    monkeypatch.setattr(
        worker_app,
        "dispatch_permit_required",
        lambda action_id: worker_policy_enabled and action_id == "httpx.web_probe.v1",
    )
    monkeypatch.setattr(task_poller, "utcnow_naive", clock.now)
    monkeypatch.setattr(task_poller, "permit_utcnow", clock.aware)
    monkeypatch.setattr(worker_app, "permit_utcnow", clock.aware)
    monkeypatch.setattr(task_poller, "get_dispatch_permit_verifier", lambda: m2a_verifier)
    monkeypatch.setattr(worker_app, "get_dispatch_permit_verifier", lambda: worker_verifier)

    handler_calls = []
    monkeypatch.setattr(worker_app, "run_httpx", lambda *_args: (
        handler_calls.append("entered") or {
            "status": "completed", "raw_output": "offline synthetic response",
            "parsed_result": {"success": True, "status_codes": [200]},
        }
    ))

    db = FakeDB(task, auth, target,
                SimpleNamespace(id=17, port=18080, protocol="tcp", service="http"),
                registry, template)
    monkeypatch.setattr(task_poller, "async_session", lambda: SessionContext(db))
    captured = {"worker_responses": [], "dispatch_calls": 0}
    real_validate = task_poller.validate_task_execution

    def inject_then_validate(tool_name, host, approval_required, approval_status):
        if mutation == "scope_revoked":
            target.scope = "127.0.0.2/32"
        elif mutation == "grant_expired":
            clock.advance(600)
        elif mutation == "approval_revoked":
            task.approval_status = "rejected"
            task.approval_epoch += 1
        return real_validate(tool_name, host, approval_required, approval_status)

    async def fake_remote(ctx):
        captured["dispatch_calls"] += 1
        request = execution_request(ctx)
        captured["request"] = request
        responses = []
        for invocation in range(replay_calls):
            worker_request = worker_app.ExecuteRequest.model_validate(request)
            if invocation == 0 and mutation_at_worker:
                if mutation_at_worker == "scope_revoked":
                    target.scope = "127.0.0.2/32"
                    target.authorization_epoch += 1
                elif mutation_at_worker == "grant_expired":
                    clock.advance(60)
                elif mutation_at_worker == "approval_revoked":
                    task.approval_status = "rejected"
                    task.approval_epoch += 1
                elif mutation_at_worker == "permit_expired":
                    clock.advance(60)
                elif mutation_at_worker == "permit_binding_mismatch":
                    request["dispatch_permit"]["binding"]["parameters_hash"] = "0" * 64
                    worker_request = worker_app.ExecuteRequest.model_validate(request)
            response = worker_app.execute(worker_request)
            responses.append(response)
        captured["worker_responses"] = responses
        if receipt_loss:
            raise TimeoutError("offline receipt-loss injection after Worker response")
        response = responses[-1]
        completed = response.get("status") == "completed"
        return ToolRunOutcome(
            command="remote:httpx_basic", raw_output=json.dumps(response),
            parsed_result=response.get("parsed_result") or {"success": completed},
            success=completed, status="completed" if completed else "failed",
            error_message=response.get("reason"),
            execution_receipt=response.get("execution_receipt"),
            worker_exchange={"delivery": "response_received", "response": response},
        )

    async def fake_fail(snapshot, reason, *, command=None, worker_exchange=None):
        task.status = "failed"
        task.execution_audit = {"worker_exchange": worker_exchange or {}, "reason": reason}
        captured["dispatch_failure"] = worker_exchange or {}

    async def fake_persist(_db, _ctx, outcome):
        task.status = outcome.status
        return 501

    with patch("worker.task_poller.validate_task_execution", side_effect=inject_then_validate), \
         patch("worker.task_poller.run_remote_tool", side_effect=fake_remote), \
         patch("worker.task_poller._fail_task", side_effect=fake_fail), \
         patch("worker.task_poller._persist_result", side_effect=fake_persist), \
         patch("worker.task_poller._record_learning_feedback", AsyncMock(return_value=False)), \
         patch("worker.task_poller.increment_target_round", AsyncMock(return_value=None)), \
         patch("worker.task_poller.analyze_tool_result_and_generate_task", AsyncMock(return_value=None)), \
         patch("worker.task_poller.finalize_target_if_idle", AsyncMock(return_value=False)):
        run_immediate(execute_task(task.id))
    captured["task_state"] = task.status
    captured["grant_state"] = "CONSUMED" if auth.consumed_count == 1 else "NOT_CONSUMED"
    captured["handler_count"] = len(handler_calls)
    captured["target_scope"] = target.scope
    captured["approval_status"] = task.approval_status
    captured["db_execute_count"] = db.execute_count
    return captured, handler_calls


@pytest.mark.parametrize("mutation,approval_required,reason", [
    ("scope_revoked", False, "TARGET_SCOPE_REVOKED"),
    ("grant_expired", False, "GRANT_EXPIRED"),
    ("approval_revoked", True, "APPROVAL_REVOKED"),
])
def test_claim_mutation_is_denied_before_worker_dispatch(
    monkeypatch, tmp_path, mutation, approval_required, reason
):
    clock = FakeClock(datetime.now(timezone.utc).replace(tzinfo=None))
    task, auth, target, port, registry, template = _fixture(clock, approval_required=approval_required)
    authority = FakeAuthority(task, auth, target, clock)
    captured, _ = _configure(monkeypatch, tmp_path, clock, task, auth, target, registry,
                             template, m2a_verifier=authority, worker_verifier=authority,
                             mutation=mutation)
    state = captured["dispatch_failure"]["dispatch_authorization"]["state"]
    actual_reason = captured["dispatch_failure"]["dispatch_authorization"]["reason_code"]
    assert state == "DENIED"
    assert actual_reason == reason
    assert captured["dispatch_calls"] == 0
    assert captured["handler_count"] == 0
    assert captured["grant_state"] == "CONSUMED"


def test_valid_authorization_reaches_worker_handler_once(monkeypatch, tmp_path):
    clock = FakeClock(datetime.now(timezone.utc).replace(tzinfo=None))
    task, auth, target, port, registry, template = _fixture(clock)
    authority = FakeAuthority(task, auth, target, clock)
    captured, _ = _configure(monkeypatch, tmp_path, clock, task, auth, target, registry,
                             template, m2a_verifier=authority, worker_verifier=authority)
    response = captured["worker_responses"][0]
    assert response["status"] == "completed"
    assert response["execution_receipt"]["dispatch_admission_state"] == "IN_FLIGHT"
    stored_request = task.execution_request
    assert stored_request["authorization_id"] == auth.id
    assert stored_request["target_id"] == target.id
    assert stored_request["dispatch_permit"]["permit_id"] == response["execution_receipt"]["dispatch_permit_id"]
    assert task.execution_request_hash == parameter_hash(stored_request)
    assert captured["handler_count"] == 1
    assert captured["task_state"] == "completed"


def test_m2a_verifier_unavailable_is_unknown_and_not_dispatched(monkeypatch, tmp_path):
    clock = FakeClock(datetime.now(timezone.utc).replace(tzinfo=None))
    task, auth, target, port, registry, template = _fixture(clock)
    captured, _ = _configure(monkeypatch, tmp_path, clock, task, auth, target, registry,
                             template, m2a_verifier=None, worker_verifier=None)
    permit_state = captured["dispatch_failure"]["dispatch_authorization"]
    assert permit_state["state"] == "UNKNOWN"
    assert permit_state["reason_code"] == "DISPATCH_PERMIT_VERIFIER_UNAVAILABLE"
    assert captured["dispatch_calls"] == 0
    assert captured["handler_count"] == 0


def test_worker_verifier_unavailable_fails_closed_after_claim(monkeypatch, tmp_path):
    clock = FakeClock(datetime.now(timezone.utc).replace(tzinfo=None))
    task, auth, target, port, registry, template = _fixture(clock)
    authority = FakeAuthority(task, auth, target, clock)
    captured, _ = _configure(monkeypatch, tmp_path, clock, task, auth, target, registry,
                             template, m2a_verifier=authority, worker_verifier=None)
    response = captured["worker_responses"][0]
    assert response["status"] == "unknown"
    assert response["dispatch_authorization"]["state"] == "UNKNOWN"
    assert response["dispatch_authorization"]["reason_code"] == "DISPATCH_PERMIT_VERIFIER_UNAVAILABLE"
    assert captured["handler_count"] == 0
    assert captured["grant_state"] == "CONSUMED"


def test_worker_rejects_opted_action_when_permit_is_missing(monkeypatch, tmp_path):
    import kali_worker.app as worker_app

    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", "127.0.0.1/32")
    monkeypatch.setenv("KALI_WORKER_REPLAY_DB_PATH", str(tmp_path / "missing-permit.sqlite3"))
    monkeypatch.setattr(settings, "enforce_target_scope", True)
    monkeypatch.setattr(settings, "allowed_scopes", "127.0.0.1/32")
    monkeypatch.setattr(settings, "dispatch_permit_required_actions", "httpx.web_probe.v1")
    handler_calls = []
    monkeypatch.setattr(worker_app, "run_httpx", lambda *_args: handler_calls.append("entered"))
    params = canonical_parameters(target="127.0.0.1", port=18080, protocol="tcp",
                                  service="http", action_id="httpx.web_probe.v1")
    ctx = TaskContext(
        task_id=86, target_id=14, tool_name="httpx_basic", host="127.0.0.1",
        port=18080, protocol="tcp", service="http", open_port_id=17,
        action_id="httpx.web_probe.v1", execution_identity=ACTION_IDENTITIES["httpx.web_probe.v1"],
        authorization_parameters=params, authorization_parameters_hash=parameter_hash(params),
        authorization_id=777, request_id=str(uuid4()), correlation_id=str(uuid4()),
        template_id=ACTION_TEMPLATES["httpx.web_probe.v1"],
        expected_worker_build_sha256=worker_build_sha256(),
    )
    request = execution_request(ctx)
    response = worker_app.execute(worker_app.ExecuteRequest.model_validate(request))
    assert response["status"] == "rejected"
    assert response["dispatch_authorization"]["state"] == "DENIED"
    assert response["reason"] == "DISPATCH_PERMIT_REQUIRED"
    assert handler_calls == []


@pytest.mark.parametrize("missing,approval_required,reason", [
    ("target_epoch", False, "AUTHORITATIVE_DISPATCH_BINDING_INCOMPLETE"),
    ("grant_epoch", False, "AUTHORITATIVE_DISPATCH_BINDING_INCOMPLETE"),
    ("approval_epoch", True, "AUTHORITATIVE_APPROVAL_EPOCH_MISSING"),
])
def test_missing_authoritative_epoch_fails_closed_before_issuance(
    monkeypatch, tmp_path, missing, approval_required, reason
):
    clock = FakeClock(datetime.now(timezone.utc).replace(tzinfo=None))
    task, auth, target, port, registry, template = _fixture(clock, approval_required=approval_required)
    if missing == "target_epoch":
        del target.authorization_epoch
    elif missing == "grant_epoch":
        del auth.target_authorization_epoch
    elif missing == "approval_epoch":
        del task.approval_epoch
    authority = FakeAuthority(task, auth, target, clock)
    captured, _ = _configure(monkeypatch, tmp_path, clock, task, auth, target, registry,
                             template, m2a_verifier=authority, worker_verifier=authority)
    permit_state = captured["dispatch_failure"]["dispatch_authorization"]
    assert permit_state["state"] == "UNKNOWN"
    assert permit_state["reason_code"] == reason
    assert authority.issue_calls == 0
    assert captured["dispatch_calls"] == 0
    assert captured["handler_count"] == 0


def test_dispatch_permit_is_opt_in_and_default_keeps_legacy_actions(monkeypatch):
    monkeypatch.setattr(settings, "dispatch_permit_required_actions", "")
    assert not dispatch_permit_required("httpx.web_probe.v1")


def test_m2a_opt_in_worker_opt_out_still_verifies_present_permit(monkeypatch, tmp_path):
    clock = FakeClock(datetime.now(timezone.utc).replace(tzinfo=None))
    task, auth, target, port, registry, template = _fixture(clock)
    m2a_authority = FakeAuthority(task, auth, target, clock)
    captured, _ = _configure(
        monkeypatch, tmp_path, clock, task, auth, target, registry, template,
        m2a_verifier=m2a_authority, worker_verifier=None,
        m2a_policy_enabled=True, worker_policy_enabled=False,
    )
    response = captured["worker_responses"][0]
    assert captured["dispatch_calls"] == 1
    assert response["dispatch_authorization"]["state"] == "UNKNOWN"
    assert response["dispatch_authorization"]["reason_code"] == "DISPATCH_PERMIT_VERIFIER_UNAVAILABLE"
    assert captured["handler_count"] == 0


def test_m2a_opt_out_worker_opt_in_rejects_missing_permit(monkeypatch, tmp_path):
    clock = FakeClock(datetime.now(timezone.utc).replace(tzinfo=None))
    task, auth, target, port, registry, template = _fixture(clock)
    captured, _ = _configure(
        monkeypatch, tmp_path, clock, task, auth, target, registry, template,
        m2a_verifier=None, worker_verifier=None,
        m2a_policy_enabled=False, worker_policy_enabled=True,
    )
    response = captured["worker_responses"][0]
    assert captured["dispatch_calls"] == 1
    assert response["dispatch_authorization"]["state"] == "DENIED"
    assert response["reason"] == "DISPATCH_PERMIT_REQUIRED"
    assert captured["handler_count"] == 0


@pytest.mark.parametrize("mutation,expected_state,reason", [
    ("permit_binding_mismatch", "DENIED", "DISPATCH_PERMIT_BINDING_HASH_MISMATCH"),
    ("permit_expired", "DENIED", "DISPATCH_PERMIT_OR_GRANT_EXPIRED"),
])
def test_worker_rejects_mismatched_or_expired_permit(
    monkeypatch, tmp_path, mutation, expected_state, reason
):
    clock = FakeClock(datetime.now(timezone.utc).replace(tzinfo=None))
    task, auth, target, port, registry, template = _fixture(clock)
    authority = FakeAuthority(task, auth, target, clock)
    captured, _ = _configure(monkeypatch, tmp_path, clock, task, auth, target, registry,
                             template, m2a_verifier=authority, worker_verifier=authority,
                             mutation_at_worker=mutation)
    response = captured["worker_responses"][0]
    assert response["status"] == "rejected"
    assert response["dispatch_authorization"]["state"] == expected_state
    assert response["dispatch_authorization"]["reason_code"] == reason
    assert captured["handler_count"] == 0


def test_duplicate_grant_replay_does_not_repeat_handler(monkeypatch, tmp_path):
    clock = FakeClock(datetime.now(timezone.utc).replace(tzinfo=None))
    task, auth, target, port, registry, template = _fixture(clock)
    authority = FakeAuthority(task, auth, target, clock)
    captured, _ = _configure(monkeypatch, tmp_path, clock, task, auth, target, registry,
                             template, m2a_verifier=authority, worker_verifier=authority,
                             replay_calls=2)
    first, second = captured["worker_responses"]
    assert first["status"] == "completed"
    assert second["status"] == "rejected"
    assert second["reason"] == "AUTHORIZATION_ALREADY_CLAIMED"
    assert captured["handler_count"] == 1
    assert authority.consume_calls == 1


def test_receipt_loss_remains_unknown_and_retry_is_not_replayed(monkeypatch, tmp_path):
    clock = FakeClock(datetime.now(timezone.utc).replace(tzinfo=None))
    task, auth, target, port, registry, template = _fixture(clock)
    authority = FakeAuthority(task, auth, target, clock)
    captured, _ = _configure(monkeypatch, tmp_path, clock, task, auth, target, registry,
                             template, m2a_verifier=authority, worker_verifier=authority,
                             receipt_loss=True)
    first = captured["worker_responses"][0]
    assert first["status"] == "completed"
    assert task.status == "failed"
    assert task.execution_audit["worker_exchange"]["delivery"] == "unknown"
    import kali_worker.app as worker_app
    retry = worker_app.execute(worker_app.ExecuteRequest.model_validate(captured["request"]))
    assert retry["status"] == "rejected"
    assert retry["reason"] == "AUTHORIZATION_ALREADY_CLAIMED"
    assert captured["handler_count"] == 1
    assert authority.consume_calls == 1


@pytest.mark.parametrize("mutation", ["scope_revoked", "grant_expired", "approval_revoked"])
def test_revoke_after_permit_issue_before_worker_admission_blocks_handler(
    monkeypatch, tmp_path, mutation
):
    approval_required = mutation == "approval_revoked"
    clock = FakeClock(datetime.now(timezone.utc).replace(tzinfo=None))
    task, auth, target, port, registry, template = _fixture(clock, approval_required=approval_required)
    authority = FakeAuthority(task, auth, target, clock)
    if mutation == "scope_revoked":
        authority.before_consume = lambda: setattr(target, "scope", "127.0.0.2/32")
        # Epochs must advance with a scope mutation.
        old = authority.before_consume
        authority.before_consume = lambda: (old(), setattr(target, "authorization_epoch", 9))
    elif mutation == "grant_expired":
        authority.before_consume = lambda: clock.advance(600)
    else:
        def revoke_approval():
            task.approval_status = "rejected"
            task.approval_epoch += 1
        authority.before_consume = revoke_approval
    captured, _ = _configure(monkeypatch, tmp_path, clock, task, auth, target, registry,
                             template, m2a_verifier=authority, worker_verifier=authority)
    response = captured["worker_responses"][0]
    assert response["dispatch_authorization"]["state"] == "DENIED"
    assert captured["handler_count"] == 0
    assert authority.issue_calls == 1
    assert authority.consume_calls == 1
