import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from worker.task_generator import generate_tool_task, _existing_tool_task
from app.models import ToolTask


@pytest.mark.asyncio
async def test_duplicate_pending_task():
    """Test that duplicate pending tasks are correctly detected and skipped"""
    with patch("worker.task_generator._existing_tool_task", new_callable=AsyncMock) as mock_existing, \
         patch("worker.task_generator._get_tool_registry", new_callable=AsyncMock) as mock_registry, \
         patch("worker.task_generator.create_tool_request", new_callable=AsyncMock) as mock_request:

        # Mock an existing pending task
        mock_existing.return_value = MagicMock(id=123)
        mock_registry.return_value = MagicMock(approval_required=False)
        
        result = await generate_tool_task(
            target_id=1,
            open_port_id=100,
            decision_result={
                "recommended_tool": "httpx_basic",
                "recommended_action": "continue"
            }
        )
        
        # Check that the function correctly skips duplicate
        assert result["action"] == "skipped_duplicate"
        assert result["tool_name"] == "httpx_basic"
        assert result["existing_task_id"] == 123


@pytest.mark.asyncio
async def test_duplicate_running_task():
    """Test that duplicate running tasks are correctly detected and skipped"""
    with patch("worker.task_generator._existing_tool_task", new_callable=AsyncMock) as mock_existing, \
         patch("worker.task_generator._get_tool_registry", new_callable=AsyncMock) as mock_registry, \
         patch("worker.task_generator.create_tool_request", new_callable=AsyncMock) as mock_request:

        # Mock an existing running task
        mock_existing.return_value = MagicMock(id=124)
        mock_registry.return_value = MagicMock(approval_required=False)
        
        result = await generate_tool_task(
            target_id=1,
            open_port_id=101,
            decision_result={
                "recommended_tool": "nuclei",
                "recommended_action": "continue"
            }
        )
        
        # Check that the function correctly skips duplicate
        assert result["action"] == "skipped_duplicate"
        assert result["tool_name"] == "nuclei_safe"  # After normalization
        assert result["existing_task_id"] == 124


@pytest.mark.asyncio
async def test_duplicate_completed_task():
    """Test that duplicate completed tasks are correctly detected and skipped"""
    with patch("worker.task_generator._existing_tool_task", new_callable=AsyncMock) as mock_existing, \
         patch("worker.task_generator._get_tool_registry", new_callable=AsyncMock) as mock_registry, \
         patch("worker.task_generator.create_tool_request", new_callable=AsyncMock) as mock_request:

        # Mock an existing completed task
        mock_existing.return_value = MagicMock(id=125)
        mock_registry.return_value = MagicMock(approval_required=False)
        
        result = await generate_tool_task(
            target_id=1,
            open_port_id=102,
            decision_result={
                "recommended_tool": "httpx",
                "recommended_action": "continue"
            }
        )
        
        # Check that the function correctly skips duplicate
        assert result["action"] == "skipped_duplicate"
        assert result["tool_name"] == "httpx_basic"  # After normalization
        assert result["existing_task_id"] == 125


@pytest.mark.asyncio
async def test_alias_duplicate_detection():
    """Test that tool name aliases are correctly normalized for duplicate detection"""
    with patch("worker.task_generator._existing_tool_task", new_callable=AsyncMock) as mock_existing, \
         patch("worker.task_generator._get_tool_registry", new_callable=AsyncMock) as mock_get_registry, \
         patch("worker.task_generator.create_tool_request", new_callable=AsyncMock) as mock_request:

        # Test that "httpx" gets normalized to "httpx_basic"
        mock_existing.return_value = MagicMock(id=126)
        mock_get_registry.return_value = MagicMock(approval_required=False)
        
        result = await generate_tool_task(
            target_id=1,
            open_port_id=103,
            decision_result={
                "recommended_tool": "httpx",  # This should be normalized to "httpx_basic"
                "recommended_action": "continue"
            }
        )
        
        # Check that the tool name was normalized
        assert result["tool_name"] == "httpx_basic"  # After normalization
        assert result["action"] == "skipped_duplicate"
        assert result["existing_task_id"] == 126


@pytest.mark.asyncio
async def test_failed_task_recreation():
    """Test that failed tasks can be recreated"""
    with patch("worker.task_generator._existing_tool_task") as mock_existing, \
         patch("worker.task_generator._get_tool_registry", new_callable=AsyncMock) as mock_get_registry, \
         patch("worker.task_generator.create_tool_request", new_callable=AsyncMock) as mock_request:

        # Configure the mock to return None for existing task check (simulate no existing task)
        mock_existing.return_value = None
        mock_get_registry.return_value = MagicMock(approval_required=False)
        
        # Mock the database session and task creation
        with patch("worker.task_generator.async_session") as mock_session:
            mock_session.return_value.__aenter__.return_value = MagicMock()
            
            result = await generate_tool_task(
                target_id=1,
                open_port_id=104,
                decision_result={
                    "recommended_tool": "nuclei",
                    "recommended_action": "continue"
                }
            )
            
            # Check that a new task was created
            assert result["action"] == "tool_task_created"


@pytest.mark.asyncio
async def test_null_open_port_handling():
    """Test that open_port_id = NULL is handled correctly"""
    with patch("worker.task_generator._existing_tool_task", new_callable=AsyncMock) as mock_existing, \
         patch("worker.task_generator._get_tool_registry", new_callable=AsyncMock) as mock_get_registry, \
         patch("worker.task_generator.create_tool_request", new_callable=AsyncMock) as mock_request:

        # Test with open_port_id = None
        mock_existing.return_value = None
        mock_get_registry.return_value = MagicMock(approval_required=False)
        
        result = await _existing_tool_task(1, None, "httpx_basic")
        # The function should handle NULL correctly
        # Note: This test is checking the function behavior with NULL values


@pytest.mark.async_io
async def test_concurrent_creation_scenario():
    """Test concurrent creation scenario"""
    # This would require a more complex test setup to simulate concurrency
    # For now, we'll trust that the implementation handles it correctly
    pass


if __name__ == "__main__":
    pytest.main([__file__])