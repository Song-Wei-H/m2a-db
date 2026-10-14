from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID
import hashlib
from pathlib import Path

import pytest

from worker.task_poller import _persist_result, _with_dispatch_correlation, execute_task, fetch_pending_tasks
from worker.tool_runner import TaskContext, ToolRunOutcome


@pytest.mark.asyncio
async def test_persist_result_commits_core_result_and_marks_feedback_pending():
    db = MagicMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.execute = AsyncMock()
    task = SimpleNamespace(execution_audit={"stage": "worker-complete"})
    db.get = AsyncMock(return_value=task)
    ctx = TaskContext(
        task_id=10,
        target_id=1,
        tool_name="httpx_basic",
        host="example.com",
        port=443,
        protocol="tcp",
        service="https",
        open_port_id=20,
        decision_score_id=30,
    )
    outcome = ToolRunOutcome(
        command="httpx -u https://example.com",
        raw_output="HTTP 200",
        parsed_result={"status_codes": [200]},
        success=True,
        status="completed",
        error_message=None,
        worker_exchange={"request_id": "test-request", "http_status": 200,
                         "application_status": "completed", "receipt_present": True},
    )

    result_id = await _persist_result(db, ctx, outcome)

    assert result_id is None
    tool_result = db.add.call_args.args[0]
    assert tool_result.target_id == 1
    assert tool_result.open_port_id == 20
    assert tool_result.tool_task_id == 10
    assert tool_result.tool_name == "httpx_basic"
    assert task.execution_audit["result_persisted"] is True
    assert task.execution_audit["learning_feedback_status"] == "pending"
    assert task.execution_audit["worker_exchange"]["request_id"] == "test-request"
    assert task.execution_audit["learning_feedback_retryable"] is True


def test_dispatch_correlation_is_a_uuid_bound_to_selected_template():
    ctx = TaskContext(
        task_id=91, target_id=2, tool_name="http_security_headers",
        host="192.0.2.5", port=18080, protocol="tcp", service="http",
        open_port_id=3,
    )
    correlated = _with_dispatch_correlation(ctx, "http_security_headers_v2")
    UUID(correlated.request_id)
    assert correlated.template_id == "http_security_headers_v2"
    assert len(correlated.expected_worker_build_sha256) == 64
    assert correlated.expected_worker_build_sha256 == hashlib.sha256(
        (Path(__file__).resolve().parents[1] / "kali_worker" / "app.py").read_bytes()
    ).hexdigest()
    assert correlated.task_id == ctx.task_id


@pytest.mark.asyncio
async def test_create_learning_feedback_records_complete_existing_schema_fields():
    from worker.learning_feedback import create_learning_feedback

    session = AsyncMock()
    tool_result = SimpleNamespace(
        id=50,
        tool_name="nuclei_safe",
        success=True,
        evidence=None,
        raw_output="",
        parsed_output={"finding_count": 0},
    )

    with patch("worker.learning_feedback.learning_engine.record_learning_feedback", AsyncMock()) as mocked_record:
        await create_learning_feedback(
            session,
            tool_result,
            decision_id=60,
            service="https",
            evidence_type="vulnerability_scan_negative",
            recommended_action="verify",
        )

    mocked_record.assert_awaited_once_with(
        session=session,
        decision_id=60,
        tool_result_id=50,
        tool_name="nuclei_safe",
        service="https",
        evidence_type="vulnerability_scan_negative",
        recommended_action="verify",
        success=True,
        learning_score=0.85,
        reason="Tool executed successfully. Useful evidence found.",
        feedback="Tool executed successfully. Useful evidence found.",
    )


class FakeScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return self

    def all(self):
        if self.value is None:
            return []
        if isinstance(self.value, list):
            return self.value
        return [self.value]


class FakeAsyncSessionContext:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, tb):
        return False


@pytest.mark.asyncio
async def test_execute_task_remote_timeout_marks_failed_and_writes_tool_result():
    task = SimpleNamespace(
        id=86,
        target_id=14,
        open_port_id=17,
        decision_score_id=52,
        tool_name="dirb_safe",
        status="pending",
        approval_required=False,
        approval_status="not_required",
        execution_authorization_id=None,
        investigation_id=None,
        action_id=None,
    )
    target = SimpleNamespace(id=14, target="198.51.100.13")
    open_port = SimpleNamespace(id=17, port=443, protocol="tcp", service="ssl/http")
    registry = SimpleNamespace(enabled=True)
    template = SimpleNamespace(enabled=True, template_id="dirb_safe_v1")

    initial_db = MagicMock()
    initial_db.begin.return_value = FakeAsyncSessionContext(initial_db)
    initial_db.execute = AsyncMock(
        side_effect=[
            FakeScalarResult(86),
            FakeScalarResult(None),
            FakeScalarResult(registry),
            FakeScalarResult(template),
        ]
    )

    async def fake_get(model, row_id):
        if model.__name__ == "ToolTask":
            return task
        if model.__name__ == "Target":
            return target
        if model.__name__ == "OpenPort":
            return open_port
        return None

    initial_db.get = AsyncMock(side_effect=fake_get)

    fail_db = MagicMock()
    fail_db.begin.return_value = FakeAsyncSessionContext(fail_db)
    fail_db.execute = AsyncMock(return_value=FakeScalarResult(None))
    fail_db.add = MagicMock()
    fail_db.flush = AsyncMock()
    failed_task = SimpleNamespace(execution_audit={"stage": "prepared"})
    fail_db.get = AsyncMock(return_value=failed_task)

    timeout_reason = "remote tool timeout after 300s: dirb_safe target=198.51.100.13 port=443"

    with patch(
        "worker.task_poller.async_session",
        side_effect=[
            FakeAsyncSessionContext(initial_db),
            FakeAsyncSessionContext(fail_db),
        ],
    ), patch("worker.task_poller.validate_task_execution"), patch(
        "worker.task_poller.run_remote_tool",
        AsyncMock(side_effect=TimeoutError(timeout_reason)),
    ), patch("worker.task_poller._record_learning_feedback", AsyncMock(return_value=False)), patch(
        "worker.task_poller.finalize_target_if_idle",
        AsyncMock(return_value=False),
    ):
        await execute_task(86)

    running_update = initial_db.execute.await_args_list[1].args[0]
    assert running_update.compile().params["status"] == "running"

    failed_update = fail_db.execute.await_args.args[0]
    assert failed_update.compile().params["status"] == "failed"
    assert failed_update.compile().params["reject_reason"] == timeout_reason

    failed_result = fail_db.add.call_args.args[0]
    assert failed_result.target_id == 14
    assert failed_result.open_port_id == 17
    assert failed_result.tool_task_id == 86
    assert failed_result.tool_name == "dirb_safe"
    assert failed_result.success is False
    assert failed_result.raw_output == timeout_reason
    assert failed_result.evidence == timeout_reason
    assert failed_result.parsed_output == {"status": "failed", "error": timeout_reason}


@pytest.mark.asyncio
async def test_fetch_pending_tasks_excludes_pending_approval_tasks():
    db = MagicMock()
    db.execute = AsyncMock(return_value=FakeScalarResult([]))

    tasks = await fetch_pending_tasks(db)

    assert tasks == []
    stmt = db.execute.await_args.args[0]
    compiled_sql = str(stmt.compile(compile_kwargs={"literal_binds": True}))
    assert "tool_tasks.status = 'pending'" in compiled_sql
    assert "tool_tasks.approval_status IN ('not_required', 'approved')" in compiled_sql
    assert "pending_approval" not in compiled_sql
