"""Integration test for the Auto Multi-Round Loop Implementation."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from sqlalchemy import select

# Add the parent directory to the path to allow imports
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from worker.auto_loop import get_next_tool_task, check_stop_conditions
from app.models import ToolTask


class FakeScalarResult:
    def __init__(self, value=None):
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
async def test_get_next_tool_task_stop_max_round():
    """Test that get_next_tool_task properly stops when max round is reached."""
    # Mock the database session and target
    with patch("worker.auto_loop.async_session") as mock_session_context:
        # Create a mock session that returns a target with current_round >= max_round
        mock_session = MagicMock()
        mock_target = MagicMock()
        mock_target.current_round = 5
        mock_target.max_round = 5
        
        # Configure the mock session's get method to return our mock target
        mock_session.get = AsyncMock(return_value=mock_target)
        mock_session.flush = AsyncMock()
        mock_session.execute = AsyncMock(return_value=FakeScalarResult(None))
        
        # Mock the session context manager
        mock_session_context.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_context.return_value.__aexit__ = AsyncMock()
        
        # Mock the decision result that would cause stopping
        decision_result = {
            "recommended_tool": "httpx",
            "recommended_action": "continue"
        }
        
        # Mock the generate_tool_task function to avoid creating actual tasks
        with patch("worker.auto_loop.generate_tool_task", new_callable=AsyncMock) as mock_generate:
            mock_generate.return_value = {"action": "tool_task_created", "tool_task_id": 1}
            
            # Call the function
            result = await get_next_tool_task(1, None, decision_result)
            
            # Check that we get the expected result
            assert result["action"] == "stop"
            assert result["stop_reason"] == "max_round_reached"


@pytest.mark.asyncio
async def test_get_next_tool_task_stop_no_next_tool():
    """Test that get_next_tool_task properly stops when there's no next tool."""
    # Mock the database session and target
    with patch("worker.auto_loop.async_session") as mock_session_context:
        # Create a mock session that returns a target with current_round < max_round
        mock_session = MagicMock()
        mock_target = MagicMock()
        mock_target.current_round = 3
        mock_target.max_round = 5
        
        # Configure the mock session's get method to return our mock target
        mock_session.get = AsyncMock(return_value=mock_target)
        mock_session.flush = AsyncMock()
        mock_session.execute = AsyncMock(return_value=FakeScalarResult(None))
        
        # Mock the session context manager
        mock_session_context.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_context.return_value.__aexit__ = AsyncMock()
        
        # Mock the decision result that would cause stopping
        decision_result = {
            "recommended_tool": None,
            "recommended_action": "continue"
        }
        
        # Mock the generate_tool_task function to avoid creating actual tasks
        with patch("worker.auto_loop.generate_tool_task", new_callable=AsyncMock) as mock_generate:
            mock_generate.return_value = {"action": "tool_task_created", "tool_task_id": 1}
            
            # Call the function
            result = await get_next_tool_task(1, None, decision_result)
            
            # Check that we get the expected result
            assert result["action"] == "stop"
            assert result["stop_reason"] == "no_next_tool"


@pytest.mark.asyncio
async def test_get_next_tool_task_stop_action():
    """Test that get_next_tool_task properly stops when action is stop."""
    # Mock the database session and target
    with patch("worker.auto_loop.async_session") as mock_session_context:
        # Create a mock session that returns a target with current_round < max_round
        mock_session = MagicMock()
        mock_target = MagicMock()
        mock_target.current_round = 3
        mock_target.max_round = 5
        
        # Configure the mock session's get method to return our mock target
        mock_session.get = AsyncMock(return_value=mock_target)
        mock_session.flush = AsyncMock()
        mock_session.execute = AsyncMock(return_value=FakeScalarResult(None))
        
        # Mock the session context manager
        mock_session_context.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_context.return_value.__aexit__ = AsyncMock()
        
        # Mock the decision result that would cause stopping
        decision_result = {
            "recommended_tool": "httpx",
            "recommended_action": "stop"
        }
        
        # Mock the generate_tool_task function to avoid creating actual tasks
        with patch("worker.auto_loop.generate_tool_task", new_callable=AsyncMock) as mock_generate:
            mock_generate.return_value = {"action": "tool_task_created", "tool_task_id": 1}
            
            # Call the function
            result = await get_next_tool_task(1, None, decision_result)
            
            # Check that we get the expected result
            assert result["action"] == "stop"
            assert result["stop_reason"] == "stop_action"


@pytest.mark.asyncio
async def test_get_next_tool_task_continue():
    """Test that get_next_tool_task properly continues when conditions are met."""
    # Mock the database session and target
    with patch("worker.auto_loop.async_session") as mock_session_context:
        # Create a mock session that returns a target with current_round < max_round
        mock_session = MagicMock()
        mock_target = MagicMock()
        mock_target.current_round = 3
        mock_target.max_round = 5
        
        # Configure the mock session's get method to return our mock target
        mock_session.get = AsyncMock(return_value=mock_target)
        mock_session.flush = AsyncMock()
        mock_session.execute = AsyncMock(return_value=FakeScalarResult(None))
        
        # Mock the session context manager
        mock_session_context.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_context.return_value.__aexit__ = AsyncMock()
        
        # Mock the decision result that would cause continuing
        decision_result = {
            "recommended_tool": "httpx",
            "recommended_action": "continue"
        }
        
        # Mock the generate_tool_task function to avoid creating actual tasks
        with patch("worker.auto_loop.generate_tool_task", new_callable=AsyncMock) as mock_generate:
            mock_generate.return_value = {"action": "tool_task_created", "tool_task_id": 1}
            
            # Call the function
            result = await get_next_tool_task(1, None, decision_result)
            
            # Check that we get the expected result
            assert result["action"] == "tool_task_created"
            assert result["tool_task_id"] == 1


@pytest.mark.asyncio
async def test_get_next_tool_task_depth_tool_requires_pending_approval():
    with patch("worker.auto_loop.async_session") as mock_session_context:
        mock_session = MagicMock()
        mock_target = MagicMock()
        mock_target.current_round = 1
        mock_target.max_round = 5
        mock_session.get = AsyncMock(return_value=mock_target)
        mock_session.flush = AsyncMock()
        mock_session.execute = AsyncMock(return_value=FakeScalarResult(None))
        mock_session_context.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_context.return_value.__aexit__ = AsyncMock()

        decision_result = {
            "recommended_tool": "nuclei_safe",
            "recommended_action": "verify",
            "requires_approval": True,
        }

        with patch("worker.auto_loop.generate_tool_task", new_callable=AsyncMock) as mock_generate:
            mock_generate.return_value = {
                "action": "tool_task_created",
                "tool_task_id": 2,
                "approval_required": True,
                "approval_status": "pending_approval",
            }

            result = await get_next_tool_task(1, 10, decision_result)

        assert result["action"] == "tool_task_created"
        assert result["approval_required"] is True
        assert result["approval_status"] == "pending_approval"
        mock_generate.assert_awaited_once()
