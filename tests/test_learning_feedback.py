import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import ToolResult
from worker.learning_feedback import (
    calculate_learning_score,
    create_learning_feedback,
    determine_evidence_type,
    determine_service,
    get_tool_result_status
)
from worker.learning_engine import record_learning_feedback


class TestLearningFeedback:
    """Test cases for learning feedback functionality."""

    def test_calculate_learning_score_success_with_evidence(self):
        """Test learning score calculation for successful execution with evidence."""
        # Create a mock ToolResult with successful execution and evidence
        tool_result = MagicMock()
        tool_result.success = True
        tool_result.parsed_output = {
            "parsed_result": {
                "finding_count": 3
            }
        }
        
        score, reason = calculate_learning_score(tool_result)
        assert score == 1.5
        assert reason == "Tool executed successfully and produced evidence."

    def test_calculate_learning_score_success_without_evidence(self):
        """Test learning score calculation for successful execution without evidence."""
        # Create a mock ToolResult with successful execution but no evidence
        tool_result = MagicMock()
        tool_result.success = True
        tool_result.parsed_output = {}
        
        score, reason = calculate_learning_score(tool_result)
        assert score == 1.0
        assert reason == "Tool executed successfully."

    def test_calculate_learning_score_failure(self):
        """Test learning score calculation for failed execution."""
        # Create a mock ToolResult with failed execution
        tool_result = MagicMock()
        tool_result.success = False
        tool_result.evidence = "Tool execution failed."
        
        score, reason = calculate_learning_score(tool_result)
        assert score == -1.0
        assert reason == "Tool execution failed."

    def test_calculate_learning_score_timeout(self):
        """Test learning score calculation for timeout."""
        # Create a mock ToolResult with timeout
        tool_result = MagicMock()
        tool_result.success = False
        tool_result.evidence = "timeout occurred"
        
        score, reason = calculate_learning_score(tool_result)
        assert score == -2.0
        assert reason == "Tool execution timed out."

    def test_calculate_learning_score_blocked(self):
        """Test learning score calculation for blocked execution."""
        # Create a mock ToolResult with blocked execution
        tool_result = MagicMock()
        tool_result.success = False
        tool_result.evidence = "Execution forbidden by policy"
        
        score, reason = calculate_learning_score(tool_result)
        assert score == -2.0
        assert reason == "Tool execution blocked by policy."

    def test_determine_evidence_type_with_parsed_output(self):
        """Test evidence type determination with parsed output."""
        # Create a mock ToolResult with parsed output containing evidence type
        tool_result = MagicMock()
        tool_result.parsed_output = {
            "evidence_type": "vulnerability"
        }
        
        evidence_type = determine_evidence_type(tool_result)
        assert evidence_type == "vulnerability"

    def test_determine_service_with_parsed_output(self):
        """Test service determination with parsed output."""
        # Create a mock ToolResult with parsed output containing service
        tool_result = MagicMock()
        tool_result.parsed_output = {
            "service": "http"
        }
        tool_result.tool_name = "nmap"
        
        service = determine_service(tool_result)
        assert service == "http"

    def test_determine_service_without_parsed_output(self):
        """Test service determination without parsed output."""
        # Create a mock ToolResult without parsed output
        tool_result = MagicMock()
        tool_result.parsed_output = None
        tool_result.tool_name = "nmap"
        
        service = determine_service(tool_result)
        assert service == "nmap"

    @pytest.mark.asyncio
    async def test_create_learning_feedback_success(self):
        """Test successful creation of learning feedback."""
        # Create a mock session and tool result
        session = AsyncMock(spec=AsyncSession)
        tool_result = MagicMock()
        tool_result.id = 1
        tool_result.success = True
        tool_result.parsed_output = {}
        tool_result.tool_name = "nmap"
        
        # Mock the calculate_learning_score function to return a fixed value for testing
        with patch('worker.learning_feedback.calculate_learning_score', return_value=(1.0, "Tool executed successfully.")), \
             patch('worker.learning_feedback.determine_evidence_type', return_value=None), \
             patch('worker.learning_feedback.determine_service', return_value="nmap"):
            
            # Mock the record_learning_feedback function
            with patch('worker.learning_engine.record_learning_feedback') as mock_record:
                await create_learning_feedback(session, tool_result)
                mock_record.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_learning_feedback_exception_handling(self):
        """Test that learning feedback creation doesn't break execution flow on exception."""
        # Create a mock session and tool result
        session = AsyncMock(spec=AsyncSession)
        tool_result = MagicMock()
        tool_result.id = 1
        tool_result.success = True
        tool_result.parsed_output = {}
        tool_result.tool_name = "nmap"
        
        # Mock the calculate_learning_score function to raise an exception
        with patch('worker.learning_feedback.calculate_learning_score', side_effect=Exception("Test exception")), \
             patch('worker.learning_engine.record_learning_feedback') as mock_record:
            
            # Even with an exception, the function should not raise an error
            await create_learning_feedback(session, tool_result)
            # The record_learning_feedback should not be called due to the exception
            mock_record.assert_not_called()

    def test_get_tool_result_status_success(self):
        """Test determination of tool result status."""
        tool_result = MagicMock()
        tool_result.success = True
        tool_result.evidence = None
        
        status = get_tool_result_status(tool_result)
        assert status == "success"

    def test_get_tool_result_status_timeout(self):
        """Test determination of tool result status for timeout."""
        tool_result = MagicMock()
        tool_result.success = False
        tool_result.evidence = "timeout occurred"
        
        status = get_tool_result_status(tool_result)
        assert status == "timeout"

    def test_get_tool_result_status_blocked(self):
        """Test determination of tool result status for blocked execution."""
        tool_result = MagicMock()
        tool_result.success = False
        tool_result.evidence = "forbidden by policy"
        
        status = get_tool_result_status(tool_result)
        assert status == "blocked"