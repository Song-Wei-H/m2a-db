"""Tests for the report generator module."""
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from worker.report_generator import generate_target_report


class FakeScalarResult:
    """Small stand-in for SQLAlchemy Result/ScalarResult."""

    def __init__(self, items):
        self._items = list(items)

    def scalars(self):
        return self

    def all(self):
        return self._items

    def first(self):
        return self._items[0] if self._items else None


class FakeAsyncSessionContext:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, tb):
        return False


def row(**kwargs):
    return SimpleNamespace(**kwargs)


def make_target():
    return row(
        id=1,
        target="example.com",
        target_type="domain",
        scope="in_scope",
        status="completed",
        current_round=2,
        max_round=5,
    )


def make_session(target, execute_results):
    session = MagicMock()
    session.get = AsyncMock(return_value=target)
    session.execute = AsyncMock(side_effect=execute_results)
    return session


@pytest.mark.asyncio
async def test_generate_target_report_success_after_removing_invalid_tool_run_eager_load():
    created_at = datetime(2026, 1, 2, 3, 4, 5)
    open_port = row(
        id=101,
        scan_run_id=201,
        ip="203.0.113.10",
        port=443,
        protocol="tcp",
        service="https",
        product="nginx",
        version="1.25",
        extra_info="tls",
        state="open",
        created_at=created_at,
    )
    tool_result = row(
        id=301,
        scan_run_id=201,
        open_port_id=101,
        tool_task_id=401,
        tool_name="httpx",
        success=True,
        command="httpx -u https://example.com",
        risk_level="medium",
        evidence="HTTP 200",
        raw_output="HTTP 200 OK",
        parsed_output={"status_code": 200},
        created_at=created_at,
    )
    tool_task = row(
        id=401,
        tool_name="httpx",
        status="completed",
        priority=3,
        open_port_id=101,
        tool_run="run-1",
        decision_score_id=501,
        approval_status="not_required",
        approval_required=False,
        approval_reason=None,
        reject_reason=None,
        created_at=created_at,
    )
    decision_score = row(
        id=501,
        open_port_id=101,
        risk_score=8.5,
        base_risk_score=7.0,
        adjusted_risk_score=8.5,
        confidence_score=0.9,
        learning_adjustment=0.2,
        runtime_adjustment=0.1,
        evidence_adjustment=1.2,
        severity="high",
        next_action="validate",
        next_tool="nuclei",
        mitre_phase="Reconnaissance",
        mitre_technique="Active Scanning",
        confidence=0.88,
        reason="Exposed HTTPS service",
        reasoning=["https exposed"],
        input_snapshot={"ports": [443]},
        waf_detected=False,
        tool_blocked=False,
        tool_timeout=False,
        created_at=created_at,
    )
    evidence_confidence = row(
        id=601,
        open_port_id=101,
        decision_score_id=501,
        tool_result_id=301,
        tool_name="httpx",
        evidence_type="http-response",
        confidence_score=0.93,
        confidence_reason="Service responded consistently",
        supporting_evidence={"status": 200},
        contradictory_evidence={},
        created_at=created_at,
    )
    normalized_result = row(
        id=602,
        open_port_id=101,
        tool_result_id=301,
        tool_name="httpx",
        evidence_type="http_service",
        normalized_output={"evidence_type": "http_service", "details": {"status_code": 200}},
        created_at=created_at,
    )
    auto_loop_decision = row(
        id=701,
        round_number=2,
        next_tool="nuclei",
        stop_reason="continue",
        created_at=created_at,
    )
    learning_feedback = row(
        id=801,
        decision_id=501,
        tool_result_id=301,
        tool_name="nuclei",
        success=True,
        service="https",
        evidence_type="template-match",
        recommended_action="validate",
        learning_score=0.8,
        reason="Useful validation",
        feedback="Keep using nuclei for HTTPS",
        created_at=created_at,
    )
    cve_match = row(
        cve="CVE-2024-NGINX-0001",
        cve_id="CVE-2024-NGINX-0001",
        open_port_id=101,
        product="nginx",
        version="1.25",
        cvss=8.8,
        cvss_score=8.8,
        severity="high",
        epss=0.72,
        kev=False,
        affected_product="nginx",
        affected_version="1.25",
        match_type="exact_cpe_version",
        match_confidence=1.0,
        match_reason="Exact product and version match from local cve_enrichment.",
        source="cpe:2.3:a:nginx:nginx:1.25:*:*:*:*:*:*:*",
    )
    session = make_session(
        make_target(),
        [
            FakeScalarResult([open_port]),
            FakeScalarResult([tool_result]),
            FakeScalarResult([tool_task]),
            FakeScalarResult([decision_score]),
            FakeScalarResult([evidence_confidence]),
            FakeScalarResult([normalized_result]),
            FakeScalarResult([auto_loop_decision]),
            FakeScalarResult([learning_feedback]),
            FakeScalarResult([cve_match]),
            FakeScalarResult([]),
        ],
    )

    with patch("worker.report_generator.async_session", return_value=FakeAsyncSessionContext(session)):
        report = await generate_target_report(1)

    session.get.assert_awaited_once()
    assert session.execute.await_count == 10
    assert report["target"] is report["target_summary"]
    assert report["target_summary"]["target_id"] == 1
    assert report["target_summary"]["open_port_count"] == 1
    assert report["target_summary"]["highest_risk_score"] == 8.5
    assert report["open_ports"][0]["port"] == 443
    assert report["open_ports"][0]["matched_cves"][0]["cve_id"] == "CVE-2024-NGINX-0001"
    assert report["open_ports"][0]["matched_cves"][0]["cve"] == "CVE-2024-NGINX-0001"
    assert report["open_ports"][0]["matched_cves"][0]["cvss_score"] == 8.8
    assert report["open_ports"][0]["matched_cves"][0]["match_reason"].startswith("Exact product")
    assert report["tool_results"][0]["tool_name"] == "httpx"
    assert report["tool_tasks"][0]["tool_run"] == "run-1"
    assert report["decision_scores"][0]["risk_score"] == 8.5
    assert report["mitre_mapping"] == [
        {
            "decision_score_id": 501,
            "mitre_phase": "Reconnaissance",
            "mitre_technique": "Active Scanning",
            "risk_score": 8.5,
            "severity": "high",
            "next_tool": "nuclei",
            "reason": "Exposed HTTPS service",
        }
    ]
    assert report["risk_ranking"]["high_risk_ports"][0]["open_port_id"] == 101
    assert report["risk_ranking"]["highest_risk_decision"]["decision_score_id"] == 501
    assert report["remediation"][0]["service"] == "https"
    assert report["remediation"][0]["requires_followup"] is False
    assert report["remediation"][0]["requires_remediation"] is False
    assert report["remediation"][0]["no_further_action"] is False
    assert report["remediation_guidance"] == [report["remediation"][0]["guidance"]]
    assert report["evidence_confidence"][0]["confidence_score"] == 0.93
    assert report["normalized_results"] == [
        {
            "normalized_result_id": 602,
            "open_port_id": 101,
            "tool_result_id": 301,
            "tool_name": "httpx",
            "evidence_type": "http_service",
            "normalized_output": {"evidence_type": "http_service", "details": {"status_code": 200}},
            "created_at": created_at,
        }
    ]
    assert report["auto_loop_decisions"][0]["reason"] == "continue"
    assert report["learning_feedback"][0]["learning_score"] == 0.8
    assert report["learning_tool_score"] == [
        {
            "tool_name": "nuclei",
            "feedback_count": 1,
            "success_count": 1,
            "avg_learning_score": 0.8,
            "final_learning_score": 0.8,
        }
    ]
    assert report["matched_cves"][0]["match_type"] == "exact_cpe_version"
    assert report["matched_cves"][0]["affected_product"] == "nginx"
    assert report["matched_cves"][0]["affected_version"] == "1.25"
    assert report["learning_feedback_summary"] == {
        "total_feedback": 1,
        "successful": 1,
        "failed": 0,
        "average_learning_score": 0.8,
        "by_tool": [
            {
                "tool_name": "nuclei",
                "total": 1,
                "successful": 1,
                "failed": 0,
                "average_learning_score": 0.8,
                "services": ["https"],
                "recommended_actions": ["validate"],
            }
        ],
    }


@pytest.mark.asyncio
async def test_generate_target_report_returns_404_when_target_is_missing():
    session = make_session(None, [])

    with patch("worker.report_generator.async_session", return_value=FakeAsyncSessionContext(session)):
        report = await generate_target_report(404)

    assert report == {"error": "Target not found", "status": 404}
    session.get.assert_awaited_once()
    session.execute.assert_not_called()


@pytest.mark.asyncio
async def test_completed_target_recommended_actions_use_latest_final_stop_only():
    old_created_at = datetime(2026, 1, 2, 3, 4, 5)
    final_created_at = datetime(2026, 1, 2, 3, 5, 5)
    historical_continue = row(
        id=501,
        open_port_id=101,
        risk_score=8.5,
        base_risk_score=7.0,
        adjusted_risk_score=8.5,
        confidence_score=0.9,
        learning_adjustment=0.2,
        runtime_adjustment=0.1,
        evidence_adjustment=1.2,
        severity="high",
        next_action="continue",
        next_tool="httpx_basic",
        mitre_phase="Initial Access",
        mitre_technique="T1190",
        confidence=0.88,
        reason="HTTP service should be probed",
        reasoning=["https exposed"],
        input_snapshot={},
        waf_detected=False,
        tool_blocked=False,
        tool_timeout=False,
        created_at=old_created_at,
    )
    final_stop = row(
        id=502,
        open_port_id=101,
        risk_score=8.5,
        base_risk_score=7.0,
        adjusted_risk_score=8.5,
        confidence_score=0.9,
        learning_adjustment=0.2,
        runtime_adjustment=0.1,
        evidence_adjustment=1.2,
        severity="high",
        next_action="stop",
        next_tool=None,
        mitre_phase="Initial Access",
        mitre_technique="T1190",
        confidence=0.88,
        reason="Target completed; no further executable tasks.",
        reasoning=["final audit"],
        input_snapshot={},
        waf_detected=False,
        tool_blocked=False,
        tool_timeout=False,
        created_at=final_created_at,
    )
    session = make_session(
        make_target(),
        [
            FakeScalarResult([]),
            FakeScalarResult([]),
            FakeScalarResult([]),
            FakeScalarResult([historical_continue, final_stop]),
            FakeScalarResult([]),
            FakeScalarResult([]),
            FakeScalarResult([]),
            FakeScalarResult([]),
            FakeScalarResult([]),
            FakeScalarResult([]),
        ],
    )

    with patch("worker.report_generator.async_session", return_value=FakeAsyncSessionContext(session)):
        report = await generate_target_report(1)

    assert report["risk_ranking"]["recommended_next_actions"] == [
        {
            "next_action": "stop",
            "next_tool": None,
            "risk_score": 8.5,
            "severity": "high",
            "reason": "Target completed; no further executable tasks.",
        }
    ]
    decision_actions = [
        (decision["decision_score_id"], decision["next_action"], decision["next_tool"])
        for decision in report["risk_ranking"]["decisions_by_risk"]
    ]
    assert (501, "continue", "httpx_basic") in decision_actions
    assert (502, "stop", None) in decision_actions


@pytest.mark.asyncio
async def test_report_remediation_flags_follow_next_action():
    created_at = datetime(2026, 1, 2, 3, 4, 5)
    decisions = [
        row(
            id=1,
            open_port_id=None,
            risk_score=9.0,
            base_risk_score=9.0,
            adjusted_risk_score=9.0,
            confidence_score=0.9,
            learning_adjustment=0,
            runtime_adjustment=0,
            evidence_adjustment=0,
            severity="critical",
            next_action="remediate",
            next_tool=None,
            mitre_phase=None,
            mitre_technique=None,
            confidence=0.9,
            reason="Critical issue",
            reasoning=[],
            input_snapshot={},
            waf_detected=False,
            tool_blocked=False,
            tool_timeout=False,
            created_at=created_at,
        ),
        row(
            id=2,
            open_port_id=None,
            risk_score=5.0,
            base_risk_score=5.0,
            adjusted_risk_score=5.0,
            confidence_score=0.8,
            learning_adjustment=0,
            runtime_adjustment=0,
            evidence_adjustment=0,
            severity="medium",
            next_action="continue",
            next_tool="dirb_safe",
            mitre_phase=None,
            mitre_technique=None,
            confidence=0.8,
            reason="Needs follow-up",
            reasoning=[],
            input_snapshot={},
            waf_detected=False,
            tool_blocked=False,
            tool_timeout=False,
            created_at=created_at,
        ),
    ]
    session = make_session(
        make_target(),
        [
            FakeScalarResult([]),
            FakeScalarResult([]),
            FakeScalarResult([]),
            FakeScalarResult(decisions),
            FakeScalarResult([]),
            FakeScalarResult([]),
            FakeScalarResult([]),
            FakeScalarResult([]),
            FakeScalarResult([]),
            FakeScalarResult([]),
        ],
    )

    with patch("worker.report_generator.async_session", return_value=FakeAsyncSessionContext(session)):
        report = await generate_target_report(1)

    by_action = {item["reason"]: item for item in report["remediation"]}
    assert by_action["Critical issue"]["requires_remediation"] is True
    assert by_action["Critical issue"]["requires_followup"] is False
    assert by_action["Critical issue"]["no_further_action"] is False
    assert by_action["Needs follow-up"]["requires_remediation"] is False
    assert by_action["Needs follow-up"]["requires_followup"] is True
    assert by_action["Needs follow-up"]["no_further_action"] is False
