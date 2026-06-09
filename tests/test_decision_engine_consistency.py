import pytest
from worker.risk_engine_v2 import decide_next_action


def test_decide_next_action_consistency():
    """Test that the decision engine follows the required consistency rules"""
    
    # Test case 1: next_tool exists, should always return "continue"
    result = decide_next_action(
        base_risk_score=1.0,
        adjusted_risk_score=1.0,
        confidence_score=0.9,
        severity="low",
        next_tool="httpx_basic",  # Tool exists
        waf_detected=False,
        tool_blocked=False,
        tool_timeout=False,
        kev_detected=False,
        max_epss=None,
        cvss=None,
    )
    
    # Should always return "continue" when next_tool exists
    assert result == "continue", f"Expected 'continue', got '{result}'"
    
    # Test case 2: KEV detection should return "remediate"
    result = decide_next_action(
        base_risk_score=8.0,
        adjusted_risk_score=8.0,
        confidence_score=0.9,
        severity="critical",
        next_tool="nuclei_safe",
        waf_detected=False,
        tool_blocked=False,
        tool_timeout=False,
        kev_detected=True,  # KEV detected
        max_epss=None,
        cvss=None,
    )
    
    assert result == "remediate", f"Expected 'remediate', got '{result}'"
    
    # Test case 3: CVSS >= 9 should return "remediate"
    result = decide_next_action(
        base_risk_score=9.0,
        adjusted_risk_score=9.0,
        confidence_score=0.9,
        severity="critical",
        next_tool="nuclei_safe",
        waf_detected=False,
        tool_blocked=False,
        tool_timeout=False,
        kev_detected=False,
        max_epss=None,
        cvss=9.5,  # High CVSS
    )
    
    assert result == "remediate", f"Expected 'remediate', got '{result}'"
    
    # Test case 4: High severity should return "verify"
    result = decide_next_action(
        base_risk_score=7.0,
        adjusted_risk_score=7.0,
        confidence_score=0.9,
        severity="high",
        next_tool="nuclei_safe",
        waf_detected=False,
        tool_blocked=False,
        tool_timeout=False,
        kev_detected=False,
        max_epss=None,
        cvss=None,
    )
    
    assert result == "verify", f"Expected 'verify', got '{result}'"
    
    # Test case 5: No tool and low severity should return "stop"
    result = decide_next_action(
        base_risk_score=1.0,
        adjusted_risk_score=1.0,
        confidence_score=0.9,
        severity="low",
        next_tool=None,  # No tool
        waf_detected=False,
        tool_blocked=False,
        tool_timeout=False,
        kev_detected=False,
        max_epss=None,
        cvss=None,
    )
    
    assert result == "stop", f"Expected 'stop', got '{result}'"


def test_original_inconsistent_state_fixed():
    """Test that the original inconsistent state is now fixed"""
    # This would be the state that was previously possible:
    # next_tool = "httpx_basic" and next_action = "stop"
    
    # Now this should be impossible - if next_tool exists, action must be "continue"
    result = decide_next_action(
        base_risk_score=1.0,
        adjusted_risk_score=1.0,
        confidence_score=0.3,  # Low confidence
        severity="low",
        next_tool="httpx_basic",  # Tool exists
        waf_detected=False,
        tool_blocked=False,
        tool_timeout=False,
        kev_detected=False,
        max_epss=None,
        cvss=None,
    )
    
    # Even with low confidence and low severity, if next_tool exists, should return "continue"
    assert result == "continue", f"Expected 'continue', got '{result}'"
    
    
def test_no_tool_scenarios():
    """Test scenarios where next_tool is None"""
    # Low severity with no tool should return "stop"
    result = decide_next_action(
        base_risk_score=1.0,
        adjusted_risk_score=1.0,
        confidence_score=0.9,
        severity="low",
        next_tool=None,
        waf_detected=False,
        tool_blocked=False,
        tool_timeout=False,
        kev_detected=False,
        max_epss=None,
        cvss=None,
    )
    
    assert result == "stop", f"Expected 'stop', got '{result}'"
    
    # Medium severity with no tool should return "stop"
    result = decide_next_action(
        base_risk_score=5.0,
        adjusted_risk_score=5.0,
        confidence_score=0.9,
        severity="medium",
        next_tool=None,
        waf_detected=False,
        tool_blocked=False,
        tool_timeout=False,
        kev_detected=False,
        max_epss=None,
        cvss=None,
    )
    
    assert result == "stop", f"Expected 'stop', got '{result}'"
