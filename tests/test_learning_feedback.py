import pytest
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import LearningFeedback, ToolResult
from worker.learning_feedback import (
    calculate_learning_score,
    calculate_confidence_delta,
    create_learning_feedback,
    determine_evidence_type,
    determine_service,
    get_tool_result_status
)
from worker.learning_engine import get_tool_learning_score, record_learning_feedback


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
        tool_result.evidence = None
        tool_result.raw_output = None
        
        score, reason = calculate_learning_score(tool_result)
        assert score == 0.85
        assert reason == "Tool executed successfully. Useful evidence found."

    def test_calculate_learning_score_success_without_evidence(self):
        """Test learning score calculation for successful execution without evidence."""
        # Create a mock ToolResult with successful execution but no evidence
        tool_result = MagicMock()
        tool_result.success = True
        tool_result.parsed_output = {}
        tool_result.evidence = None
        tool_result.raw_output = None
        
        score, reason = calculate_learning_score(tool_result)
        assert score == 0.5
        assert reason == "Tool executed successfully. Empty parsed output."

    def test_calculate_learning_score_failure(self):
        """Test learning score calculation for failed execution."""
        # Create a mock ToolResult with failed execution
        tool_result = MagicMock()
        tool_result.success = False
        tool_result.evidence = "Tool execution failed."
        tool_result.raw_output = None
        tool_result.parsed_output = {}
        
        score, reason = calculate_learning_score(tool_result)
        assert score == 0.1
        assert reason == "Tool execution failed. Empty parsed output."

    def test_calculate_learning_score_timeout(self):
        """Test learning score calculation for timeout."""
        # Create a mock ToolResult with timeout
        tool_result = MagicMock()
        tool_result.success = False
        tool_result.evidence = "timeout occurred"
        tool_result.raw_output = None
        tool_result.parsed_output = {}
        
        score, reason = calculate_learning_score(tool_result)
        assert score == 0.0
        assert reason == "Tool execution failed. Empty parsed output. Timeout observed."

    def test_calculate_learning_score_blocked(self):
        """Test learning score calculation for blocked execution."""
        # Create a mock ToolResult with blocked execution
        tool_result = MagicMock()
        tool_result.success = False
        tool_result.evidence = "Execution forbidden by policy"
        tool_result.raw_output = None
        tool_result.parsed_output = {}
        
        score, reason = calculate_learning_score(tool_result)
        assert score == 0.0
        assert reason == "Tool execution failed. Empty parsed output. Blocked execution observed."

    def test_calculate_learning_score_high_confidence_clamps(self):
        tool_result = MagicMock()
        tool_result.success = True
        tool_result.evidence = "confirmed"
        tool_result.raw_output = None
        tool_result.parsed_output = {"evidence_type": "http_service", "confidence_score": 0.95}

        score, reason = calculate_learning_score(tool_result)

        assert score == 0.95
        assert "High confidence evidence." in reason

    def test_calculate_confidence_delta(self):
        assert calculate_confidence_delta(
            expected_confidence=0.80,
            actual_outcome_confidence=0.95,
        ) == 0.15

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
            with patch('worker.learning_engine.record_learning_feedback', new_callable=AsyncMock) as mock_record:
                await create_learning_feedback(session, tool_result)
                mock_record.assert_awaited_once()

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


def test_learning_feedback_decision_id_references_decision_scores():
    foreign_keys = list(LearningFeedback.__table__.c.decision_id.foreign_keys)

    assert len(foreign_keys) == 1
    assert foreign_keys[0].target_fullname == "decision_scores.id"


def test_learning_feedback_fk_migration_targets_decision_scores():
    migration = Path("initdb/015_learning_feedback_decision_score_fk.sql").read_text()

    assert "REFERENCES decision_scores(id)" in migration
    assert "REFERENCES llm_decisions" not in migration


class FakeFirstResult:
    def __init__(self, row):
        self.row = row

    def first(self):
        return self.row


@pytest.mark.asyncio
async def test_record_learning_feedback_writes_complete_fields():
    session = AsyncMock(spec=AsyncSession)

    await record_learning_feedback(
        session=session,
        decision_id=1,
        tool_result_id=2,
        tool_name="httpx_basic",
        service="https",
        evidence_type="http_service",
        recommended_action="continue",
        success=True,
        was_success=True,
        confidence_delta=0.15,
        learning_score=0.85,
        reason="HTTP service confirmed",
    )

    sql = str(session.execute.await_args.args[0])
    params = session.execute.await_args.args[1]
    assert "was_success" in sql
    assert "confidence_delta" in sql
    assert params["was_success"] is True
    assert params["confidence_delta"] == 0.15
    assert params["learning_score"] == 0.85


@pytest.mark.asyncio
async def test_risk_engine_learning_score_default():
    session = AsyncMock(spec=AsyncSession)
    session.execute = AsyncMock(return_value=FakeFirstResult(None))

    assert await get_tool_learning_score(session, "missing") == 0.5


@pytest.mark.asyncio
async def test_risk_engine_learning_score_uses_view_value():
    session = AsyncMock(spec=AsyncSession)
    session.execute = AsyncMock(return_value=FakeFirstResult(MagicMock(final_learning_score=0.85)))

    assert await get_tool_learning_score(session, "httpx_basic") == 0.85
