"""Tests for the Auto Multi-Round Loop Implementation."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

# Add the parent directory to the path to allow imports
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.models import DecisionScore, ToolTask
from worker.auto_loop import (
    check_stop_conditions,
    finalize_target_if_idle,
    get_next_tool_task,
    increment_target_round,
    log_auto_loop_decision,
    STOP_REASONS
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

@pytest.mark.asyncio
async def test_check_stop_conditions_max_round_reached():
    """Test that stop condition is triggered when max round is reached."""
    should_stop, stop_reason = await check_stop_conditions(
        target_id=1,
        current_round=5,
        max_round=5,
        next_tool="httpx",
        next_action="continue",
        existing_tool_task=None
    )
    
    assert should_stop is True
    assert stop_reason == STOP_REASONS["max_round_reached"]


@pytest.mark.asyncio
async def test_check_stop_conditions_no_next_tool():
    """Test that stop condition is triggered when next_tool is None."""
    should_stop, stop_reason = await check_stop_conditions(
        target_id=1,
        current_round=1,
        max_round=5,
        next_tool=None,
        next_action="continue",
        existing_tool_task=None
    )
    
    assert should_stop is True
    assert stop_reason == STOP_REASONS["no_next_tool"]


@pytest.mark.asyncio
async def test_check_stop_conditions_stop_action():
    """Test that stop condition is triggered when next_action is 'stop'."""
    should_stop, stop_reason = await check_stop_conditions(
        target_id=1,
        current_round=1,
        max_round=5,
        next_tool="httpx",
        next_action="stop",
        existing_tool_task=None
    )
    
    assert should_stop is True
    assert stop_reason == STOP_REASONS["stop_action"]


@pytest.mark.asyncio
async def test_check_stop_conditions_duplicate_tool():
    """Test that stop condition is triggered when duplicate tool is detected."""
    # Create a mock ToolTask to simulate an existing task
    existing_task = ToolTask(
        id=1,
        target_id=1,
        tool_name="httpx",
        status="pending"
    )
    
    should_stop, stop_reason = await check_stop_conditions(
        target_id=1,
        current_round=1,
        max_round=5,
        next_tool="httpx",
        next_action="continue",
        existing_tool_task=existing_task
    )
    
    assert should_stop is True
    assert stop_reason == STOP_REASONS["duplicate_tool"]


@pytest.mark.asyncio
async def test_check_stop_conditions_should_continue():
    """Test that no stop condition is triggered when conditions are not met."""
    should_stop, stop_reason = await check_stop_conditions(
        target_id=1,
        current_round=1,
        max_round=5,
        next_tool="httpx",
        next_action="continue",
        existing_tool_task=None
    )
    
    assert should_stop is False
    assert stop_reason is None


@pytest.mark.asyncio
async def test_finalize_target_if_idle_marks_completed_when_no_active_tasks():
    session = MagicMock()
    session.get = AsyncMock(return_value=type("TargetRow", (), {"id": 17, "current_round": 1, "max_round": 5})())
    session.execute = AsyncMock(
        side_effect=[
            FakeScalarResult(None),
            FakeScalarResult(None),
            FakeScalarResult(None),
            FakeScalarResult(None),
        ]
    )

    completed = await finalize_target_if_idle(17, session=session, stop_reason="no_next_tool")

    assert completed is True
    update_stmt = session.execute.await_args_list[3].args[0]
    assert update_stmt.compile().params["status"] == "completed"


@pytest.mark.asyncio
async def test_finalize_target_if_idle_does_not_complete_with_active_tasks():
    session = MagicMock()
    session.execute = AsyncMock(return_value=FakeScalarResult(86))

    completed = await finalize_target_if_idle(17, session=session, stop_reason="no_next_tool")

    assert completed is False
    assert session.execute.await_count == 1


@pytest.mark.asyncio
async def test_finalize_target_if_idle_adds_final_audit_decision_after_completed_next_tool():
    latest_decision = DecisionScore(
        id=54,
        target_id=18,
        open_port_id=22,
        risk_score=2.4,
        base_risk_score=2.0,
        adjusted_risk_score=2.4,
        confidence_score=0.8,
        severity="low",
        next_action="continue",
        next_tool="httpx_basic",
        mitre_phase="Initial Access",
        mitre_technique="T1190",
        confidence=0.8,
    )
    session = MagicMock()
    session.get = AsyncMock(return_value=type("TargetRow", (), {"id": 18, "current_round": 1, "max_round": 5})())
    session.execute = AsyncMock(
        side_effect=[
            FakeScalarResult(None),
            FakeScalarResult([]),
            FakeScalarResult(latest_decision),
            FakeScalarResult(86),
            FakeScalarResult(None),
        ]
    )
    session.add = MagicMock()
    session.flush = AsyncMock()

    completed = await finalize_target_if_idle(18, session=session)

    assert completed is True
    final_decision = session.add.call_args.args[0]
    assert final_decision.target_id == 18
    assert final_decision.open_port_id == 22
    assert final_decision.risk_score == 2.4
    assert final_decision.next_action == "stop"
    assert final_decision.next_tool is None
    assert final_decision.reason == "Target completed; no further executable tasks."
    assert final_decision.input_snapshot["previous_decision_score_id"] == 54


@pytest.mark.asyncio
async def test_increment_target_round():
    """Test that target round is incremented correctly."""
    # This test would need to mock the database session
    # We'll test this by mocking the async_session context manager
    pass  # Implementation would go here


@pytest.mark.asyncio
async def test_log_auto_loop_decision():
    """Test that auto loop decisions are logged correctly."""
    # This test would need to mock the database session and AutoLoopDecision model
    # We'll test this by mocking the database session
    pass  # Implementation would go here
