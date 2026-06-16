from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from worker.task_poller import _persist_result, execute_task
from worker.tool_runner import TaskContext, ToolRunOutcome


@pytest.mark.asyncio
async def test_persist_result_creates_learning_feedback_with_task_context():
    db = MagicMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.execute = AsyncMock()
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
    )

    with patch("worker.learning_feedback.create_learning_feedback", AsyncMock()) as mocked_feedback:
        result_id = await _persist_result(db, ctx, outcome)

    assert result_id is None
    mocked_feedback.assert_awaited_once()
    _, tool_result = mocked_feedback.await_args.args[:2]
    assert tool_result.target_id == 1
    assert tool_result.open_port_id == 20
    assert tool_result.tool_task_id == 10
    assert tool_result.tool_name == "httpx_basic"
    assert mocked_feedback.await_args.kwargs == {
        "decision_id": 30,
        "service": "https",
        "recommended_action": None,
    }


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
            confidence_delta=0.0,
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
        was_success=True,
        confidence_delta=0.0,
        learning_score=0.85,
        reason="Tool executed successfully. Useful evidence found.",
        feedback="Tool executed successfully. Useful evidence found.",
    )


class FakeScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


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
        tool_name="httpx_basic",
        approval_required=False,
        approval_status="not_required",
    )
    target = SimpleNamespace(id=14, target="198.51.100.13")
    open_port = SimpleNamespace(id=17, port=443, protocol="tcp", service="ssl/http")
    registry = SimpleNamespace(enabled=True)
    template = SimpleNamespace(enabled=True)

    initial_db = MagicMock()
    initial_db.begin.return_value = FakeAsyncSessionContext(initial_db)
    initial_db.execute = AsyncMock(
        side_effect=[
            FakeScalarResult(86),
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

    timeout_reason = "remote tool timeout after 300s: httpx_basic target=198.51.100.13 port=443"

    with patch(
        "worker.task_poller.async_session",
        side_effect=[
            FakeAsyncSessionContext(initial_db),
            FakeAsyncSessionContext(fail_db),
        ],
    ), patch("worker.task_poller.validate_task_execution"), patch(
        "worker.task_poller.run_remote_tool",
        AsyncMock(side_effect=TimeoutError(timeout_reason)),
    ), patch("worker.learning_feedback.create_learning_feedback", AsyncMock()):
        await execute_task(86)

    failed_update = fail_db.execute.await_args.args[0]
    assert failed_update.compile().params["status"] == "failed"
    assert failed_update.compile().params["reject_reason"] == timeout_reason

    failed_result = fail_db.add.call_args.args[0]
    assert failed_result.target_id == 14
    assert failed_result.open_port_id == 17
    assert failed_result.tool_task_id == 86
    assert failed_result.tool_name == "httpx_basic"
    assert failed_result.success is False
    assert failed_result.raw_output == timeout_reason
    assert failed_result.evidence == timeout_reason
    assert failed_result.parsed_output == {"status": "failed", "error": timeout_reason}
