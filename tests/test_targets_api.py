from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.main import app


def sample_report():
    target_summary = {
        "target_id": 1,
        "target": "example.com",
        "target_type": "domain",
        "scope": "internal",
        "status": "completed",
        "current_round": 2,
        "max_rounds": 5,
        "open_port_count": 1,
        "tool_result_count": 1,
        "decision_count": 1,
        "decision_score_count": 1,
        "learning_feedback_count": 1,
        "highest_risk_score": 8.5,
        "highest_severity": "high",
    }
    return {
        "target_summary": target_summary,
        "target": target_summary,
        "open_ports": [{"port": 443, "service": "https"}],
        "tool_results": [
            {
                "tool_name": "httpx",
                "success": True,
                "service": "https",
                "evidence_type": "http_service",
                "risk_level": "medium",
                "created_at": None,
                "parsed_output": {"status_code": 200},
                "raw_output": "must not leak",
            }
        ],
        "tool_tasks": [{"tool_name": "httpx", "status": "completed"}],
        "decision_scores": [
            {
                "risk_score": 8.5,
                "severity": "high",
                "next_action": "stop",
                "next_tool": None,
                "confidence": 0.9,
                "reason": "done",
                "mitre_phase": "Reconnaissance",
                "mitre_technique": "Active Scanning",
            }
        ],
        "mitre_mapping": [{"mitre_phase": "Reconnaissance", "mitre_technique": "Active Scanning"}],
        "risk_ranking": {"highest_risk_decision": {"risk_score": 8.5}},
        "remediation": [{"service": "https", "guidance": "Patch and validate."}],
        "remediation_guidance": ["Patch and validate."],
        "evidence_confidence": [{"confidence_score": 0.9}],
        "auto_loop_decisions": [{"round": 2, "next_tool": "nuclei"}],
        "learning_feedback": [
            {
                "tool_name": "httpx",
                "success": True,
                "confidence_delta": 0.15,
                "learning_score": 0.85,
                "reason": "HTTP service confirmed",
                "created_at": None,
            }
        ],
        "learning_feedback_summary": {"total_feedback": 1},
    }


def test_get_target_summary_uses_report_generator_slice():
    client = TestClient(app)
    mocked_report = AsyncMock(return_value=sample_report())

    with patch("app.api.targets.generate_target_report", mocked_report):
        response = client.get("/targets/1/summary")

    assert response.status_code == 200
    expected = dict(sample_report()["target_summary"])
    expected.pop("decision_score_count")
    assert response.json() == expected
    mocked_report.assert_awaited_once_with(1)


def test_get_target_tool_results_uses_report_generator_slice():
    client = TestClient(app)
    mocked_report = AsyncMock(return_value=sample_report())

    with patch("app.api.targets.generate_target_report", mocked_report):
        response = client.get("/targets/1/tool-results")

    assert response.status_code == 200
    assert response.json() == [
        {
            "tool_name": "httpx",
            "success": True,
            "evidence_type": "http_service",
            "service": "https",
            "risk_level": "medium",
            "created_at": None,
            "parsed_output": {"status_code": 200},
        }
    ]
    mocked_report.assert_awaited_once_with(1)


def test_get_target_decisions_uses_report_generator_slice():
    client = TestClient(app)
    mocked_report = AsyncMock(return_value=sample_report())

    with patch("app.api.targets.generate_target_report", mocked_report):
        response = client.get("/targets/1/decisions")

    assert response.status_code == 200
    assert response.json() == sample_report()["decision_scores"]
    mocked_report.assert_awaited_once_with(1)


def test_dashboard_endpoints_return_404_when_report_generator_cannot_find_target():
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
