from datetime import datetime
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from pydantic import TypeAdapter

from app.main import app
from app.schemas import TargetReportResponse


def sample_report(**overrides):
    now = datetime(2026, 1, 2, 3, 4, 5)
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
            "tool_result_count": 1,
            "decision_count": 2,
            "learning_feedback_count": 1,
        },
        "target": {"target_id": 18, "target": "198.51.100.13"},
        "open_ports": [
            {
                "ip": "198.51.100.13",
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "product": "nginx",
                "version": "1.25",
                "state": "open",
            }
        ],
        "tool_results": [
            {
                "tool_name": "httpx_basic",
                "success": True,
                "evidence_type": "http_service",
                "service": "https",
                "risk_level": "medium",
                "created_at": now,
                "raw_output": "large output should not be returned",
                "parsed_output": {"status_code": 200, "title": "OK"},
            }
        ],
        "decision_scores": [
            {
                "risk_score": 8.5,
                "severity": "high",
                "next_action": "continue",
                "next_tool": "httpx_basic",
                "confidence": 0.88,
                "reason": "HTTP service should be probed",
                "mitre_phase": "Reconnaissance",
                "mitre_technique": "Active Scanning",
            },
            {
                "risk_score": 8.5,
                "severity": "high",
                "next_action": "stop",
                "next_tool": None,
                "confidence": 0.88,
                "reason": "Target completed; no further executable tasks.",
                "mitre_phase": "Reconnaissance",
                "mitre_technique": "Active Scanning",
            },
        ],
        "risk_ranking": {
            "highest_risk_score": 8.5,
            "highest_severity": "high",
            "recommended_next_actions": [
                {
                    "next_action": "stop",
                    "next_tool": None,
                    "risk_score": 8.5,
                    "severity": "high",
                    "reason": "Target completed; no further executable tasks.",
                }
            ],
            "decisions_by_risk": [],
        },
        "mitre_mapping": [
            {
                "mitre_phase": "Reconnaissance",
                "mitre_technique": "Active Scanning",
            }
        ],
        "learning_feedback": [
            {
                "tool_name": "httpx_basic",
                "success": True,
                "confidence_delta": 0.15,
                "learning_score": 0.85,
                "reason": "HTTP service confirmed",
            }
        ],
        "remediation": [
            {
                "severity": "high",
                "recommendation": "Patch the framework/server, enforce TLS, and run safe vulnerability validation.",
            }
        ],
        "matched_cves": [
            {
                "cve_id": "CVE-2024-NGINX-0001",
                "open_port_id": 1,
                "cvss": 8.8,
                "epss": 0.72,
                "kev": False,
                "match_type": "exact_cpe_version",
                "match_confidence": 1.0,
            }
        ],
        "tool_tasks": [],
        "normalized_results": [],
        "remediation_guidance": [
            "Patch the framework/server, enforce TLS, and run safe vulnerability validation."
        ],
        "evidence_confidence": [],
        "auto_loop_decisions": [],
        "learning_feedback_summary": {"total_feedback": 1},
    }
    report.update(overrides)
    return report


def test_get_target_report_returns_valid_report_contract():
    client = TestClient(app)
    mocked_report = AsyncMock(return_value=sample_report())

    with patch("app.api.targets.generate_target_report", mocked_report):
        response = client.get("/targets/18/report")

    assert response.status_code == 200
    body = response.json()
    assert set(
        [
            "target_summary",
            "open_ports",
            "tool_results",
            "decision_scores",
            "risk_ranking",
            "mitre_mapping",
            "learning_feedback",
            "remediation",
        ]
    ).issubset(body)
    assert body["target_summary"]["target_id"] == 18
    assert body["target_summary"]["learning_feedback_count"] == 1
    assert body["open_ports"][0]["service"] == "https"
    assert body["tool_results"][0]["parsed_output"]["status_code"] == 200
    assert "raw_output" not in body["tool_results"][0]
    assert body["matched_cves"][0]["match_type"] == "exact_cpe_version"
    mocked_report.assert_awaited_once_with(18)


def test_get_target_report_returns_404_for_missing_target():
    client = TestClient(app)
    mocked_report = AsyncMock(return_value={"error": "Target not found", "status": 404})

    with patch("app.api.targets.generate_target_report", mocked_report):
        response = client.get("/targets/404/report")

    assert response.status_code == 404
    assert response.json() == {"detail": "Target not found"}


def test_get_target_report_handles_empty_target_sections():
    client = TestClient(app)
    empty_report = sample_report(
        target_summary={
            "target_id": 19,
            "target": "empty.example",
            "target_type": "domain",
            "scope": "internal",
            "status": "pending",
            "current_round": 1,
            "max_rounds": 5,
            "open_port_count": 0,
            "tool_result_count": 0,
            "decision_count": 0,
            "learning_feedback_count": 0,
        },
        open_ports=[],
        tool_results=[],
        decision_scores=[],
        risk_ranking={
            "highest_risk_score": None,
            "highest_severity": None,
            "recommended_next_actions": [],
        },
        mitre_mapping=[],
        learning_feedback=[],
        remediation=[],
    )
    mocked_report = AsyncMock(return_value=empty_report)

    with patch("app.api.targets.generate_target_report", mocked_report):
        response = client.get("/targets/19/report")

    assert response.status_code == 200
    body = response.json()
    assert body["open_ports"] == []
    assert body["tool_results"] == []
    assert body["risk_ranking"]["recommended_next_actions"] == []


def test_completed_target_report_uses_authoritative_final_stop_action():
    client = TestClient(app)
    mocked_report = AsyncMock(return_value=sample_report())

    with patch("app.api.targets.generate_target_report", mocked_report):
        response = client.get("/targets/18/report")

    assert response.status_code == 200
    recommended = response.json()["risk_ranking"]["recommended_next_actions"]
    assert recommended == [
        {
            "next_action": "stop",
            "next_tool": None,
            "risk_score": 8.5,
            "severity": "high",
            "reason": "Target completed; no further executable tasks.",
        }
    ]


def test_report_response_contains_mitre_learning_and_remediation_sections():
    client = TestClient(app)
    mocked_report = AsyncMock(return_value=sample_report())

    with patch("app.api.targets.generate_target_report", mocked_report):
        response = client.get("/targets/18/report")

    assert response.status_code == 200
    body = response.json()
    assert body["mitre_mapping"] == [
        {"mitre_phase": "Reconnaissance", "mitre_technique": "Active Scanning"}
    ]
    assert body["learning_feedback"][0]["learning_score"] == 0.85
    assert body["remediation"][0]["severity"] == "high"
    assert "recommendation" in body["remediation"][0]


def test_target_report_response_schema_validates_nulls_and_optional_fields():
    adapter = TypeAdapter(TargetReportResponse)
    validated = adapter.validate_python(
        {
            "target_summary": {
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
            },
            "open_ports": [],
            "tool_results": [{"tool_name": None, "parsed_output": None}],
            "decision_scores": [{"next_tool": None, "mitre_phase": None}],
            "risk_ranking": {
                "highest_risk_score": None,
                "highest_severity": None,
                "recommended_next_actions": [],
            },
            "mitre_mapping": [],
            "learning_feedback": [{"confidence_delta": None}],
            "remediation": [{"severity": None, "recommendation": None}],
        }
    )

    assert validated.target_summary.target_id == 20
    assert validated.tool_results[0].parsed_output is None
