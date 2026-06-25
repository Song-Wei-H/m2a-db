from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models import CveEnrichment, PortCveMatch
from worker.cve_enrichment import summarize_cve_risk
from worker.risk_engine_v3 import calculate_risk
from worker.task_poller import _persist_result
from worker.tool_runner import TaskContext, ToolRunOutcome


class FakeScalarResult:
    def __init__(self, rows=None, one=None):
        self.rows = rows or []
        self.one = one

    def scalar_one_or_none(self):
        return self.one

    def scalars(self):
        return self

    def all(self):
        return self.rows


@pytest.mark.asyncio
async def test_persist_httpx_result_invokes_cve_matching_after_tool_result_flush():
    db = MagicMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.execute = AsyncMock(
        side_effect=[
            FakeScalarResult(
                rows=[
                    CveEnrichment(
                        cve="CVE-2024-OPENCTI-0001",
                        affected_vendor="citeum",
                        affected_product="opencti",
                        affected_version=None,
                        cvss_score=6.5,
                        severity="medium",
                        epss=None,
                        kev=False,
                        source="nvd",
                    )
                ]
            ),
            FakeScalarResult(one=None),
            FakeScalarResult(one=None),
        ]
    )
    ctx = TaskContext(
        task_id=86,
        target_id=18,
        tool_name="httpx_basic",
        host="198.51.100.13",
        port=443,
        protocol="tcp",
        service="https",
        open_port_id=17,
        decision_score_id=54,
    )
    outcome = ToolRunOutcome(
        command="httpx -json",
        raw_output="{}",
        parsed_result={
            "webserver": "nginx",
            "cpe": [{"cpe": "cpe:2.3:a:citeum:opencti:*:*:*:*:*:*:*:*"}],
        },
        success=True,
        status="completed",
        error_message=None,
    )

    with patch("worker.learning_feedback.create_learning_feedback", AsyncMock()):
        await _persist_result(db, ctx, outcome)

    inserted_matches = [call.args[0] for call in db.add.call_args_list if isinstance(call.args[0], PortCveMatch)]
    assert inserted_matches
    assert inserted_matches[0].target_id == 18
    assert inserted_matches[0].open_port_id == 17
    assert inserted_matches[0].match_type == "cpe_product_only"
    assert inserted_matches[0].match_confidence == 0.6


@pytest.mark.asyncio
async def test_cve_summary_uses_only_high_confidence_version_matches_for_engine_inputs():
    exact = SimpleNamespace(
        cvss=8.8,
        epss=0.72,
        kev=False,
        match_confidence=1.0,
        match_type="exact_cpe_version",
        version="1.25.5",
        cve_id="CVE-2024-NGINX-0001",
    )
    product_only = SimpleNamespace(
        cvss=9.8,
        epss=0.99,
        kev=True,
        match_confidence=0.6,
        match_type="cpe_product_only",
        version=None,
        cve_id="CVE-2024-OPENCTI-0001",
    )
    db = MagicMock()
    db.execute = AsyncMock(return_value=FakeScalarResult(rows=[product_only, exact]))

    summary = await summarize_cve_risk(db, target_id=18, open_port_id=17)

    assert summary.cve_count == 2
    assert summary.max_cvss == 8.8
    assert summary.max_epss == 0.72
    assert summary.has_kev is False
    assert summary.best_match_type == "exact_cpe_version"


def test_decision_score_reasoning_contains_cve_match_trace():
    result = calculate_risk(
        target_id=18,
        open_port_id=17,
        service="https",
        port=443,
        cvss=8.8,
        epss=0.72,
        kev=False,
        tool_name="httpx_basic",
        parsed_output={
            "parser_success": True,
            "status_code": 200,
            "cve_summary": {
                "cve_count": 3,
                "best_cve": "CVE-2024-NGINX-0001",
                "max_cvss": 8.8,
                "max_epss": 0.72,
                "has_kev": False,
                "best_match_type": "exact_cpe_version",
                "best_match_confidence": 1.0,
            },
        },
        raw_output="",
        base_confidence=0.93,
        learning_feedback={"success_rate": 0.85},
    )

    trace = result.reasoning[0]
    assert trace["cve_factor"] == {
        "match_count": 3,
        "best_cve": "CVE-2024-NGINX-0001",
        "cvss": 8.8,
        "epss": 0.72,
        "kev": False,
        "match_type": "exact_cpe_version",
        "match_confidence": 1.0,
    }
    assert trace["match_count"] == 3
    assert trace["cvss"] == 8.8
    assert trace["epss"] == 0.72
    assert trace["kev"] is False
    assert trace["match_type"] == "exact_cpe_version"


def test_product_only_cve_does_not_directly_create_high_or_critical_engine_input():
    result = calculate_risk(
        target_id=18,
        open_port_id=17,
        service="https",
        port=443,
        cvss=None,
        epss=None,
        kev=False,
        tool_name="httpx_basic",
        parsed_output={
            "parser_success": True,
            "cve_summary": {
                "cve_count": 1,
                "best_cve": "CVE-2024-OPENCTI-0001",
                "max_cvss": None,
                "max_epss": None,
                "has_kev": False,
                "best_match_type": "cpe_product_only",
                "best_match_confidence": 0.6,
            },
        },
    )

    assert result.reasoning[0]["match_type"] == "cpe_product_only"
    assert result.reasoning[0]["cvss"] is None
    assert result.severity in {"low", "medium"}


@pytest.mark.asyncio
async def test_persist_httpx_result_without_local_cve_data_does_not_crash():
    db = MagicMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.execute = AsyncMock(
        side_effect=[
            FakeScalarResult(rows=[]),
            FakeScalarResult(one=None),
        ]
    )
    ctx = TaskContext(
        task_id=87,
        target_id=18,
        tool_name="httpx_basic",
        host="198.51.100.13",
        port=443,
        protocol="tcp",
        service="https",
        open_port_id=17,
        decision_score_id=54,
    )
    outcome = ToolRunOutcome(
        command="httpx -json",
        raw_output="{}",
        parsed_result={"webserver": "nginx", "technologies": ["Nginx"]},
        success=True,
        status="completed",
        error_message=None,
    )

    with patch("worker.learning_feedback.create_learning_feedback", AsyncMock()):
        await _persist_result(db, ctx, outcome)

    inserted_matches = [call.args[0] for call in db.add.call_args_list if isinstance(call.args[0], PortCveMatch)]
    assert inserted_matches == []
