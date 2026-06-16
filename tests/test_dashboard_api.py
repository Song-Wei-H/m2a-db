from datetime import datetime
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from pydantic import TypeAdapter

from app.database import get_db
from app.main import app
from app.schemas import (
    DashboardOverviewResponse,
    DecisionResponse,
    LearningFeedbackResponse,
    TargetSummaryResponse,
    ToolResultResponse,
)


def sample_report(**overrides):
    older = datetime(2026, 1, 2, 3, 4, 5)
    newer = datetime(2026, 1, 2, 3, 5, 5)
    report = {
        "target_summary": {
            "target_id": 18,
            "target": "198.51.100.13",
            "target_type": "ip",
            "scope": "internal",
            "status": "completed",
            "current_round": 2,
            "max_rounds": 5,
            "open_port_count": 1,
            "tool_result_count": 2,
            "decision_count": 2,
            "learning_feedback_count": 2,
            "highest_risk_score": 8.5,
            "highest_severity": "high",
        },
        "tool_results": [
            {
                "tool_name": "nmap_service",
                "success": True,
                "service": "https",
                "evidence_type": "open_port",
                "risk_level": "low",
                "created_at": older,
                "raw_output": "must not leak",
                "parsed_output": {"ports": [{"port": 443}]},
            },
            {
                "tool_name": "httpx_basic",
                "success": True,
                "service": "https",
                "evidence_type": "http_service",
                "risk_level": "medium",
                "created_at": newer,
                "raw_output": "must not leak",
                "parsed_output": {"status_code": 200},
            },
        ],
        "decision_scores": [
            {
                "risk_score": 8.5,
                "severity": "high",
                "next_action": "stop",
                "next_tool": None,
                "confidence": 0.92,
                "reason": "Target completed; no further executable tasks.",
                "mitre_phase": "Reconnaissance",
                "mitre_technique": "Active Scanning",
            },
            {
                "risk_score": 4.0,
                "severity": "medium",
                "next_action": "continue",
                "next_tool": "httpx_basic",
                "confidence": 0.7,
                "reason": "Probe web service",
                "mitre_phase": None,
                "mitre_technique": None,
            },
        ],
        "learning_feedback": [
            {
                "tool_name": "nmap_service",
                "success": True,
                "confidence_delta": 0.1,
                "learning_score": 0.8,
                "reason": "Port confirmed",
                "created_at": older,
            },
            {
                "tool_name": "httpx_basic",
                "success": True,
                "confidence_delta": 0.15,
                "learning_score": 0.85,
                "reason": "HTTP service confirmed",
                "created_at": newer,
            },
        ],
    }
    report.update(overrides)
    return report


def test_target_summary_endpoint_returns_lightweight_summary():
    client = TestClient(app)
    mocked_report = AsyncMock(return_value=sample_report())

    with patch("app.api.targets.generate_target_report", mocked_report):
        response = client.get("/targets/18/summary")

    assert response.status_code == 200
    assert response.json() == sample_report()["target_summary"]
    mocked_report.assert_awaited_once_with(18)


def test_tool_results_endpoint_is_newest_first_and_excludes_raw_output():
    client = TestClient(app)
    mocked_report = AsyncMock(return_value=sample_report())

    with patch("app.api.targets.generate_target_report", mocked_report):
        response = client.get("/targets/18/tool-results")

    assert response.status_code == 200
    body = response.json()
    assert [item["tool_name"] for item in body] == ["httpx_basic", "nmap_service"]
    assert body[0]["parsed_output"] == {"status_code": 200}
    assert "raw_output" not in body[0]


def test_decisions_endpoint_returns_highest_risk_first():
    client = TestClient(app)
    mocked_report = AsyncMock(return_value=sample_report())

    with patch("app.api.targets.generate_target_report", mocked_report):
        response = client.get("/targets/18/decisions")

    assert response.status_code == 200
    body = response.json()
    assert [item["risk_score"] for item in body] == [8.5, 4.0]
    assert body[0]["next_action"] == "stop"


def test_learning_feedback_endpoint_is_newest_first():
    client = TestClient(app)
    mocked_report = AsyncMock(return_value=sample_report())

    with patch("app.api.targets.generate_target_report", mocked_report):
        response = client.get("/targets/18/learning-feedback")

    assert response.status_code == 200
    body = response.json()
    assert [item["tool_name"] for item in body] == ["httpx_basic", "nmap_service"]
    assert body[0]["learning_score"] == 0.85


def test_dashboard_overview_endpoint_returns_aggregate_counts():
    client = TestClient(app)
    fake_db = AsyncMock()
    fake_db.scalar = AsyncMock(side_effect=[10, 7, 2, 1, 120, 90, 90, 3, 5, 11, 22])

    async def override_get_db():
        yield fake_db

    app.dependency_overrides[get_db] = override_get_db
    try:
        response = client.get("/dashboard/overview")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == {
        "targets_total": 10,
        "targets_completed": 7,
        "targets_running": 2,
        "targets_failed": 1,
        "tool_results_total": 120,
        "decisions_total": 90,
        "learning_feedback_total": 90,
        "cve_backed_findings": 3,
        "critical_findings": 5,
        "high_findings": 11,
        "medium_findings": 22,
    }
    assert fake_db.scalar.await_count == 11


def test_dashboard_endpoints_return_404_for_missing_target():
    client = TestClient(app)
    mocked_report = AsyncMock(return_value={"error": "Target not found", "status": 404})

    with patch("app.api.targets.generate_target_report", mocked_report):
        for path in (
            "/targets/404/summary",
            "/targets/404/tool-results",
            "/targets/404/decisions",
            "/targets/404/learning-feedback",
        ):
            response = client.get(path)
            assert response.status_code == 404
            assert response.json() == {"detail": "Target not found"}

    assert mocked_report.await_count == 4


def test_dashboard_response_schemas_validate_nulls_and_empty_collections():
    TypeAdapter(TargetSummaryResponse).validate_python(
        {
            "target_id": 20,
            "target": None,
            "target_type": None,
            "scope": None,
            "status": None,
            "current_round": None,
            "max_rounds": None,
            "open_port_count": 0,
            "tool_result_count": 0,
            "decision_count": 0,
            "learning_feedback_count": 0,
            "highest_risk_score": None,
            "highest_severity": None,
        }
    )
    TypeAdapter(list[ToolResultResponse]).validate_python([{"tool_name": None, "parsed_output": None}])
    TypeAdapter(list[DecisionResponse]).validate_python([{"next_tool": None, "mitre_phase": None}])
    TypeAdapter(list[LearningFeedbackResponse]).validate_python([{"confidence_delta": None}])
    overview = TypeAdapter(DashboardOverviewResponse).validate_python({})

    assert overview.targets_total == 0
