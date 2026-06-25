from worker.risk_engine_v2 import decide_next_action


def action(**overrides):
    params = {
        "base_risk_score": 5.0,
        "adjusted_risk_score": 5.0,
        "confidence_score": 0.9,
        "severity": "medium",
        "next_tool": "httpx_basic",
        "waf_detected": False,
        "tool_blocked": False,
        "tool_timeout": False,
        "kev_detected": False,
        "max_epss": None,
        "cvss": None,
    }
    params.update(overrides)
    return decide_next_action(**params)


def test_critical_kev_beats_discovery_continue():
    assert action(kev_detected=True, next_tool="nuclei_safe") == "remediate"


def test_critical_cvss_beats_discovery_continue():
    assert action(cvss=9.8, next_tool="nuclei_safe") == "remediate"


def test_high_epss_beats_discovery_continue():
    assert action(max_epss=0.91, next_tool="nuclei_safe") == "verify"


def test_high_severity_verifies_before_continue():
    assert action(severity="high", next_tool="httpx_basic") == "verify"


def test_discovery_continue_only_after_priority_rules():
    assert action(severity="medium", next_tool="httpx_basic") == "continue"


def test_blocker_low_signal_stops_without_overriding_critical_rules():
    assert action(tool_timeout=True, base_risk_score=1.0, next_tool="httpx_basic") == "stop"
    assert action(tool_timeout=True, base_risk_score=7.0, next_tool="httpx_basic") == "verify"
