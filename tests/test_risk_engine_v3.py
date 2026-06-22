from unittest.mock import patch

from worker.risk_engine_v3 import calculate_risk, severity_from_adjusted_score


def risk(**overrides):
    params = {
        "target_id": 1,
        "open_port_id": 10,
        "service": "https",
        "port": 443,
        "cvss": None,
        "epss": None,
        "kev": False,
        "tool_name": "httpx_basic",
        "parsed_output": {"parser_success": True, "status_code": 200, "success": True},
        "raw_output": "",
        "base_confidence": 0.7,
        "learning_feedback": None,
    }
    params.update(overrides)
    return calculate_risk(**params)


def test_cvss_only_scoring_uses_v3_components():
    result = risk(cvss=9.8, parsed_output={})

    assert result.base_risk_score == 7.39
    assert result.severity == "high"
    assert result.reasoning[0]["engine"] == "risk_engine_v3"
    assert result.reasoning[0]["cvss"] == 9.8


def test_cvss_plus_epss_increases_risk():
    cvss_only = risk(cvss=8.0, epss=None)
    with_epss = risk(cvss=8.0, epss=0.9)

    assert with_epss.base_risk_score > cvss_only.base_risk_score
    assert with_epss.reasoning[0]["epss"] == 0.9


def test_kev_boost_can_make_critical():
    result = risk(cvss=9.5, epss=0.9, kev=True)

    assert result.base_risk_score == 10.0
    assert result.severity == "critical"
    assert result.next_action == "continue"


def test_learning_score_adjustment_is_applied():
    without_learning = risk(learning_feedback=None)
    with_learning = risk(learning_feedback={"success_rate": 0.85})

    assert with_learning.learning_adjustment == 0.35
    assert with_learning.adjusted_risk_score > without_learning.adjusted_risk_score
    assert with_learning.reasoning[0]["learning_score"] == 0.85


def test_evidence_confidence_adjustment_is_applied():
    low_confidence = risk(base_confidence=0.4)
    high_confidence = risk(base_confidence=0.95)

    assert high_confidence.evidence_adjustment > low_confidence.evidence_adjustment
    assert high_confidence.confidence_score > low_confidence.confidence_score


def test_runtime_adjustment_handles_timeout_and_blocking():
    result = risk(raw_output="command timeout blocked by waf")

    assert result.runtime_adjustment < 0
    assert result.tool_timeout is True
    assert result.tool_blocked is True
    assert result.waf_detected is True


def test_severity_thresholds_are_centralized():
    assert severity_from_adjusted_score(9.0) == "critical"
    assert severity_from_adjusted_score(7.0) == "high"
    assert severity_from_adjusted_score(4.0) == "medium"
    assert severity_from_adjusted_score(1.0) == "low"
    assert severity_from_adjusted_score(0.0) == "info"


def test_fallback_to_v2_when_v3_raises():
    with patch("worker.risk_engine_v3._calculate_risk_v3_primary", side_effect=ValueError("boom")):
        result = risk(cvss=7.0)

    assert result.reasoning[0]["engine"] == "risk_engine_v2_fallback"
    assert result.reasoning[0]["fallback_reason"] == "boom"
    assert result.risk_score > 0


def test_invalid_parsed_output_falls_back_to_v2():
    result = risk(parsed_output=["not", "a", "dict"])

    assert result.reasoning[0]["engine"] == "risk_engine_v2_fallback"
    assert result.risk_score > 0


def test_missing_cve_data_still_scores_service_exposure():
    result = risk(cvss=None, epss=None, kev=False)

    assert result.base_risk_score == 2.0
    assert result.reasoning[0]["cvss"] is None
    assert result.reasoning[0]["epss"] is None


def test_no_evidence_does_not_crash_and_reduces_adjusted_score():
    result = risk(parsed_output={})

    assert result.evidence_adjustment < 0
    assert result.adjusted_risk_score < result.base_risk_score
