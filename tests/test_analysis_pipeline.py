import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from sqlalchemy import select

from worker.analysis_pipeline import analyze_tool_result_and_generate_task, _existing_tool_task
from app.models import ToolTask


class FakeAsyncSessionContext:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, tb):
        return False


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


def make_fake_session():
    session = MagicMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.get = AsyncMock(return_value=None)
    session.execute = AsyncMock(return_value=FakeScalarResult())
    session.begin = MagicMock(return_value=FakeAsyncSessionContext(session))
    return session


@pytest.mark.asyncio
async def test_analysis_pipeline_httpx_basic_semantics():
    # Mock database dependencies to avoid real DB connections
    fake_session = make_fake_session()
    with patch("worker.analysis_pipeline.get_next_tool_task", new_callable=AsyncMock) as mock_generate, \
         patch("worker.analysis_pipeline.async_session", return_value=FakeAsyncSessionContext(fake_session)), \
         patch("worker.analysis_pipeline.get_learning_feedback", new_callable=AsyncMock) as mock_feedback, \
         patch("worker.analysis_pipeline.summarize_cve_risk", new_callable=AsyncMock) as mock_cve:
        
        # Mock return values
        mock_generate.return_value = {
            "action": "tool_task_created",
            "tool_task_id": 42,
        }
        mock_feedback.return_value = {
            "success_rate": 0.85,
            "false_positive_rate": 0.1,
            "tool_name": "httpx_basic",
            "evidence_type": "http_service"
        }
        mock_cve.return_value = MagicMock(
            max_cvss=5.0,
            max_epss=0.2,
            has_kev=False,
            total_score=3.0,
            best_cve="CVE-2020-1234",
            cve_count=1,
            best_match_type="service",
            best_match_confidence=0.8
        )

        results = await analyze_tool_result_and_generate_task(
            target_id=1,
            open_port_id=1,
            tool_name="httpx_basic",
            parsed_output={
                "status_codes": [200],
                "urls": ["http://192.0.2.22"],
            },
            raw_output="http://192.0.2.22 [200]",
            tool_result_id=99,
            ctx=None,
            decision_score_id=None,
        )

    assert len(results) == 1

    result = results[0]

    # Verify evidence mapping
    assert result["evidence"]["tool"] == "httpx_basic"
    assert result["evidence"]["evidence_type"] == "http_service"
    assert result["evidence"]["evidence_ref"] == "tool_result:99"
    assert result["evidence"]["details"]["status_code"] == 200

    # Verify MITRE mapping
    assert result["mitre_mapping"]["technique_id"] == "T1190"

    # Verify confidence scoring
    assert result["confidence_result"]["severity"] in {
        "high",
        "critical",
    }

    # Verify decision engine recommendation
    assert result["decision_result"]["recommended_tool"] == "nuclei_safe"
    # Verify task generation was called
    mock_generate.assert_awaited_once()


@pytest.mark.asyncio
async def test_decision_engine_remediate_kev():
    """Test that KEV detection results in remediate action"""
    fake_session = make_fake_session()
    with patch("worker.analysis_pipeline.get_next_tool_task", new_callable=AsyncMock) as mock_generate, \
         patch("worker.analysis_pipeline.async_session", return_value=FakeAsyncSessionContext(fake_session)), \
         patch("worker.analysis_pipeline.get_learning_feedback", new_callable=AsyncMock) as mock_feedback, \
         patch("worker.analysis_pipeline.summarize_cve_risk", new_callable=AsyncMock) as mock_cve:
        
        mock_generate.return_value = {
            "action": "tool_task_created",
            "tool_task_id": 43,
        }
        mock_feedback.return_value = {
            "success_rate": 0.9,
            "false_positive_rate": 0.05,
            "tool_name": "nuclei_safe",
            "evidence_type": "vulnerability"
        }
        mock_cve.return_value = MagicMock(
            max_cvss=9.8,
            max_epss=0.9,
            has_kev=True,
            total_score=9.5,
            best_cve="CVE-2023-12345",
            cve_count=1,
            best_match_type="kev",
            best_match_confidence=0.95
        )

        results = await analyze_tool_result_and_generate_task(
            target_id=1,
            open_port_id=1,
            tool_name="nuclei_safe",
            parsed_output={
                "finding_count": 1,
                "cve": "CVE-2023-12345",
                "kev": True,
            },
            raw_output="Found KEV: CVE-2023-12345",
            tool_result_id=100,
            ctx=None,
            decision_score_id=None,
        )

        result = results[0]
        assert result["decision_result"]["recommended_action"] == "remediate"


@pytest.mark.asyncio
async def test_decision_engine_verify_high_risk():
    """Test verify action for high risk scenarios"""
    fake_session = make_fake_session()
    with patch("worker.analysis_pipeline.get_next_tool_task", new_callable=AsyncMock) as mock_generate, \
         patch("worker.analysis_pipeline.async_session", return_value=FakeAsyncSessionContext(fake_session)), \
         patch("worker.analysis_pipeline.get_learning_feedback", new_callable=AsyncMock) as mock_feedback, \
         patch("worker.analysis_pipeline.summarize_cve_risk", new_callable=AsyncMock) as mock_cve:
        
        mock_generate.return_value = {
            "action": "tool_task_created",
            "tool_task_id": 44,
        }
        mock_feedback.return_value = {
            "success_rate": 0.7,
            "false_positive_rate": 0.2,
            "tool_name": "httpx_basic",
            "evidence_type": "http_service"
        }
        mock_cve.return_value = MagicMock(
            max_cvss=7.5,
            max_epss=0.3,
            has_kev=False,
            total_score=6.8,
            best_cve="CVE-2021-5678",
            cve_count=2,
            best_match_type="cvss",
            best_match_confidence=0.75
        )

        results = await analyze_tool_result_and_generate_task(
            target_id=1,
            open_port_id=1,
            tool_name="httpx_basic",
            parsed_output={
                "status_codes": [500],
                "urls": ["http://192.0.2.22"],
            },
            raw_output="http://192.0.2.22 [500]",
            tool_result_id=101,
            ctx=None,
            decision_score_id=None,
        )

        result = results[0]
        assert result["decision_result"]["recommended_action"] == "verify"


@pytest.mark.asyncio
async def test_decision_engine_stop_no_tool():
    """Test stop action when no tool is available"""
    fake_session = make_fake_session()
    with patch("worker.analysis_pipeline.get_next_tool_task", new_callable=AsyncMock) as mock_generate, \
         patch("worker.analysis_pipeline.async_session", return_value=FakeAsyncSessionContext(fake_session)), \
         patch("worker.analysis_pipeline.get_learning_feedback", new_callable=AsyncMock) as mock_feedback, \
         patch("worker.analysis_pipeline.summarize_cve_risk", new_callable=AsyncMock) as mock_cve:
        
        mock_generate.return_value = {
            "action": "tool_task_created",
            "tool_task_id": 45,
        }
        mock_feedback.return_value = {
            "success_rate": 0.3,
            "false_positive_rate": 0.5,
            "tool_name": "unknown_service",
            "evidence_type": "generic"
        }
        mock_cve.return_value = MagicMock(
            max_cvss=1.0,
            max_epss=0.01,
            has_kev=False,
            total_score=0.5,
            best_cve=None,
            cve_count=0,
            best_match_type="generic",
            best_match_confidence=0.3
        )

        results = await analyze_tool_result_and_generate_task(
            target_id=1,
            open_port_id=1,
            tool_name="unknown_service",
            parsed_output={
                "status": "no_service",
            },
            raw_output="No service detected",
            tool_result_id=102,
            ctx=None,
            decision_score_id=None,
        )

        result = results[0]
        # Verify that the action is stop when no tool is selected
        assert result["decision_result"]["recommended_action"] == "stop"


@pytest.mark.asyncio
async def test_analysis_pipeline_decision_consistency():
    """Test that the analysis pipeline properly uses the runtime risk engine"""
    # Mock database dependencies to avoid real DB connections
    fake_session = make_fake_session()
    with patch("worker.analysis_pipeline.get_next_tool_task", new_callable=AsyncMock) as mock_generate, \
         patch("worker.analysis_pipeline.async_session", return_value=FakeAsyncSessionContext(fake_session)), \
         patch("worker.analysis_pipeline.get_learning_feedback", new_callable=AsyncMock) as mock_feedback, \
         patch("worker.analysis_pipeline.summarize_cve_risk", new_callable=AsyncMock) as mock_cve:
        
        # Mock return values
        mock_generate.return_value = {
            "action": "tool_task_created",
            "tool_task_id": 42,
        }
        mock_feedback.return_value = {
            "success_rate": 0.85,
            "false_positive_rate": 0.1,
            "tool_name": "httpx_basic",
            "evidence_type": "http_service"
        }
        mock_cve.return_value = MagicMock(
            max_cvss=5.0,
            max_epss=0.2,
            has_kev=False,
            total_score=3.0,
            best_cve="CVE-2020-1234",
            cve_count=1,
            best_match_type="service",
            best_match_confidence=0.8
        )

        results = await analyze_tool_result_and_generate_task(
            target_id=1,
            open_port_id=1,
            tool_name="httpx_basic",
            parsed_output={
                "status_codes": [200],
                "urls": ["http://192.0.2.22"],
            },
            raw_output="http://192.0.2.22 [200]",
            tool_result_id=99,
            ctx=None,
            decision_score_id=None,
        )

        # Verify that the decision engine properly enforces the rules
        assert len(results) == 1

        result = results[0]

        # Verify decision engine recommendation follows the required consistency rules
        assert result["decision_result"]["recommended_action"] in {"continue", "verify", "remediate", "stop"}
        
        # Verify evidence mapping
        assert result["evidence"]["tool"] == "httpx_basic"
        assert result["evidence"]["evidence_type"] == "http_service"
        assert result["evidence"]["evidence_ref"] == "tool_result:99"
        assert result["evidence"]["details"]["status_code"] == 200
        
        # Verify MITRE mapping
        assert result["mitre_mapping"]["technique_id"] == "T1190"
        
        # Verify confidence scoring
        assert result["confidence_result"]["severity"] in {
            "high",
            "critical",
        }
        
        # Verify decision engine recommendation
        assert result["decision_result"]["recommended_tool"] == "nuclei_safe"
        assert result["decision_result"]["recommended_action"] == "continue"
        
        # Verify task generation was called
        mock_generate.assert_awaited_once()


@pytest.mark.asyncio
async def test_duplicate_tool_task_prevention():
    """Test that duplicate ToolTask generation is properly prevented"""
    # Mock the database and dependencies
    fake_session = make_fake_session()
    with patch("worker.analysis_pipeline.get_next_tool_task", new_callable=AsyncMock) as mock_generate, \
         patch("worker.analysis_pipeline.async_session", return_value=FakeAsyncSessionContext(fake_session)), \
         patch("worker.analysis_pipeline.get_learning_feedback", new_callable=AsyncMock) as mock_feedback:
        mock_feedback.return_value = {"success_rate": 0.85, "false_positive_rate": 0.1}
        
        # Mock that a task already exists
        existing_task = MagicMock()
        existing_task.id = 123
        # Mock the task generation to return our existing task
        mock_generate.return_value = {
            "action": "skipped_duplicate",
            "tool_name": "httpx_basic",
            "existing_task_id": 123
        }
        
        # Call the function with a scenario that would create a duplicate
        results = await analyze_tool_result_and_generate_task(
            target_id=13,
            open_port_id=100,  # Some open port ID
            tool_name="httpx_basic",
            parsed_output={
                "status_codes": [200],
                "urls": ["http://192.0.2.22"],
            },
            raw_output="http://192.0.2.22 [200]",
            tool_result_id=99,
            decision_score_id=None,
        )
        
        # Verify that the function properly skips duplicate task creation
        assert len(results) == 1
        result = results[0]
        # We're checking that the task result contains the proper duplicate information
        assert result["task_result"]["action"] == "skipped_duplicate"
        assert result["task_result"]["tool_name"] == "httpx_basic"
        assert result["task_result"]["existing_task_id"] == 123


@pytest.mark.asyncio
async def test_duplicate_tool_task_prevention_with_normalization():
    """Test that tool name normalization works with duplicate checking"""
    # Mock the database and dependencies
    fake_session = make_fake_session()
    with patch("worker.analysis_pipeline.get_next_tool_task", new_callable=AsyncMock) as mock_generate, \
         patch("worker.analysis_pipeline.async_session", return_value=FakeAsyncSessionContext(fake_session)), \
         patch("worker.analysis_pipeline.get_learning_feedback", new_callable=AsyncMock) as mock_feedback:
        mock_feedback.return_value = {"success_rate": 0.85, "false_positive_rate": 0.1}
        
        # Mock that a task already exists with normalized tool name
        existing_task = MagicMock()
        existing_task.id = 124
        # Mock the task generation to return our existing task
        mock_generate.return_value = {
            "action": "skipped_duplicate",
            "tool_name": "httpx_basic",  # Normalized name
            "existing_task_id": 124
        }
        
        # Call the function with a scenario that would create a duplicate
        results = await analyze_tool_result_and_generate_task(
            target_id=13,
            open_port_id=100,
            tool_name="httpx",  # This should be normalized to "httpx_basic"
            parsed_output={
                "status_codes": [200],
                "urls": ["http://192.0.2.22"],
            },
            raw_output="http://192.0.2.22 [200]",
            tool_result_id=100,
            decision_score_id=100,
        )
        
        # Verify that the function properly skips duplicate task creation with normalized tool name
        assert len(results) == 1
        result = results[0]
        # We're checking that the task result contains the proper duplicate information
        assert result["task_result"]["action"] == "skipped_duplicate"
        assert result["task_result"]["tool_name"] == "httpx_basic"  # Normalized name
        assert result["task_result"]["existing_task_id"] == 124


@pytest.mark.asyncio
async def test_analysis_pipeline_creates_stop_decision_when_no_normalized_evidence():
    fake_session = make_fake_session()
    added_rows = []

    def add_row(row):
        added_rows.append(row)

    async def flush_rows():
        for index, row in enumerate(added_rows, start=200):
            if getattr(row, "id", None) is None:
                row.id = index

    fake_session.add.side_effect = add_row
    fake_session.flush.side_effect = flush_rows

    with patch("worker.analysis_pipeline.normalize_tool_result", return_value=[]), \
         patch("worker.analysis_pipeline.get_next_tool_task", new_callable=AsyncMock) as mock_next, \
         patch("worker.analysis_pipeline.async_session", return_value=FakeAsyncSessionContext(fake_session)):
        mock_next.return_value = {
            "action": "stop",
            "stop_reason": "no_next_tool",
            "target_completed": True,
        }

        results = await analyze_tool_result_and_generate_task(
            target_id=17,
            open_port_id=21,
            tool_name="httpx_basic",
            parsed_output={"tool_name": "httpx_basic", "success": True},
            raw_output="",
            tool_result_id=300,
            decision_score_id=199,
        )

    assert len(results) == 1
    decision = added_rows[0]
    assert decision.next_action == "stop"
    assert decision.next_tool is None
    assert decision.reason == "httpx_basic produced no normalized evidence; stopping auto loop"
    mock_next.assert_awaited_once()
    assert mock_next.await_args.kwargs["decision_result"]["recommended_action"] == "stop"
    assert mock_next.await_args.kwargs["decision_result"]["recommended_tool"] is None
    assert results[0]["task_result"]["target_completed"] is True
