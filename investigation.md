# Investigation of Runtime Decision Inconsistency

## 1. calculate_risk_v3() call path

The calculate_risk_v3 function is called from worker/analysis_pipeline.py:

```python
risk_v3 = calculate_risk_v3(
    target_id=target_id,
    open_port_id=open_port_id,
    service=details.get("service") or evidence.get("service"),
    port=details.get("port") or evidence.get("port"),
    cvss=details.get("cvss") or details.get("cvss_score"),
    epss=details.get("epss") or details.get("epss_score"),
    kev=bool(details.get("kev") or details.get("is_kev")),
    tool_name=tool_name,
    parsed_output=parsed_output,
    raw_output=raw_output,
    base_confidence=confidence_result.get("confidence_score", 0.7),
    learning_feedback=feedback,
)
```

## 2. Where risk_v3.next_action is assigned

Looking at worker/risk_engine_v3.py, it's a wrapper that calls worker/risk_engine_v2.py:

```python
def calculate_risk_v3(
    *,
    target_id: int,
    open_port_id: int | None,
    service: str | None,
    port: int | None,
    cvss: float | None,
    epss: float | None,
    kev: bool,
    tool_name: str,
    parsed_output: dict[str, Any],
    raw_output: str = "",
    base_confidence: float = 0.7,
    learning_feedback: dict[str, Any] | None = None,
) -> RiskV21Result:
```

## 3. Assignments to next_action in the codebase

### In worker/risk_engine_v2.py (via worker/risk_engine_v21.py)

Looking at the decide_next_action function:

```python
def decide_next_action(
    *,
    base_risk_score: float,
    adjusted_risk_score: float,
    confidence_score: float,
    severity: str,
    next_tool: str | None,
    waf_detected: bool,
    tool_blocked: bool,
    tool_timeout: bool,
    kev_detected: bool,
    max_epss: float | None,
    cvss: float | None,
) -> str:
    # Priority 1: KEV or CVSS >= 9.0
    if kev_detected:
        return "remediate"
    
    if cvss is not None and cvss >= 9.0:
        return "remediate"
    
    # Priority 2: Verification required conditions
    if base_risk_score >= 6 and confidence_score < 0.5:
        return "verify"

    if waf_detected or tool_blocked or tool_timeout:
        if base_risk_score >= 6:
            return "verify"
    
    if max_epss is not None and max_epss >= 0.8:
        return "verify"

    if severity == "critical":
        return "verify"
    
    if severity == "high":
        return "verify"
    
    # Priority 3: Consistency rule - if next_tool exists, action must be continue
    if next_tool is not None:
        return "continue"
    
    # Priority 4: No tool available
    if severity == "low":
        return "stop"
    
    return "stop"
```

### In worker/risk_engine_v2.py, the select_next_tool function:

```python
def select_next_tool(
    *,
    service: str | None,
    port: int | None,
    adjusted_risk_score: float,
) -> str | None:
    service_name = (service or "").lower()

    if service_name in {"http", "https", "http-alt", "ssl/http"} or port in HTTP_PORTS:
        if adjusted_risk_score >= 6:
            return "nuclei_safe"
        return "httpx_basic"

    if service_name == "ssh" or port == 22:
        return "ssh-enum"

    if service_name in {"mysql", "mariadb"} or port == 3306:
        return "mysql-info"

    return None
```

## 4. Root cause analysis

The issue is that the decision engine is correctly implemented, but there seems to be a mismatch between the decision_result (which contains next_action and next_tool) and how it's being used in the runtime.

Looking at the analysis_pipeline.py, the decision_result is built from risk_v3.next_tool and risk_v3.next_action:

```python
decision_result = {
    "recommended_tool": risk_v3.next_tool,  # This comes from risk_v3
    "recommended_action": risk_v3.next_action,  # This is where the issue might be
    "priority": (
        100 if risk_v3.severity == "critical"
        else 80 if risk_v3.severity == "high"
        else 50 if risk_v3.severity == "medium"
        else 10
    ),
    "requires_approval": risk_v3.next_action
    in {"verify", "remediate"},
    "risk_score": risk_v3.risk_score,
    "risk_factors": {
        "base_risk_score": risk_v3.base_risk_score,
        "adjusted_risk_score": risk_v3.adjusted_risk_score,
        "confidence_score": risk_v3.confidence_score,
        "learning_adjustment": risk_v3.learning_adjustment,
        "runtime_adjustment": risk_v3.runtime_adjustment,
        "evidence_adjustment": risk_v3.evidence_adjustment,
        "waf_detected": risk_v3.waf_detected,
        "tool_blocked": risk_v3.tool_blocked,
        "tool_timeout": risk_v3.tool_timeout,
    },
    "reasoning": risk_v3.reasoning,
}
```

The root cause seems to be that the decision engine is correctly implemented, but there might be an issue with how the values are being assigned in the runtime.

Let's examine the decision engine implementation:

Historical note: `worker/decision_engine.py` has since been archived under
`_archive/legacy_unused/worker_decision_engine.py`. At the time of this
investigation, it contained a function that created a RiskV21Result:

```python
def calculate_risk_v21():
    # ... calculations ...
    next_action = decide_next_action(
        base_risk_score=base_risk_score,
        adjusted_risk_score=adjusted_risk_score,
        confidence_score=confidence_score,
        severity=severity,
        next_tool=next_tool,
        waf_detected=waf_detected,
        tool_blocked=tool_blocked,
        tool_timeout=tool_timeout,
        kev_detected=kev_detected,
        max_epss=max_epss,
        cvss=cvss,
    )
    
    return RiskV21Result(
        risk_score=risk_score,
        base_risk_score=base_risk_score,
        adjusted_risk_score=adjusted_risk_score,
        confidence_score=confidence_score,
        learning_adjustment=learning_adjustment,
        runtime_adjustment=runtime_adjustment,
        evidence_adjustment=evidence_adjustment,
        waf_detected=waf_detected,
        tool_blocked=tool_blocked,
        tool_timeout=tool_timeout,
        tool_timeout=tool_timeout,
        severity=severity,
        confidence=confidence_score,
        next_tool=next_tool,
        next_action=next_action,  # This is where the issue might be
        reasoning=reasoning,
    )
```

The root cause seems to be that the decision engine is correctly implemented, but there might be an issue with how the values are being assigned in the runtime.

Looking at the select_next_tool function, we can see that it returns specific tools for specific services:
- For HTTP-like services, it returns "nuclei_safe" or "httpx_basic"
- For SSH services, it returns "ssh-enum"
- For MySQL/MariaDB services, it returns "mysql-info"

The issue is that the decision engine is correctly assigning next_tool and next_action, but there seems to be a mismatch in how these values are being used in the runtime.

Looking at the decide_next_action function in risk_engine_v2.py, we can see that it correctly implements the rules:
1. KEV or CVSS >= 9.0 => remediate
2. high risk verification => verify
3. next_tool is not None => continue
4. next_tool is None => stop

But there's a problem with the consistency between next_tool and next_action. Let's look at the specific case mentioned in the issue:

The runtime is still producing:
- next_action='stop'
- next_tool='httpx_basic'

and

- next_action='stop'
- next_tool='ssh-enum'

This is inconsistent with the rules in decide_next_action function which states that if next_tool is not None, then next_action should be "continue".

Let's trace through what happens in the select_next_tool function:

For HTTP services:
- If adjusted_risk_score >= 6: return "nuclei_safe"
- Otherwise: return "httpx_basic"

For SSH services:
- return "ssh-enum"

The issue is that the select_next_tool function is correctly returning a tool name, but the decide_next_action function is returning "stop" instead of "continue" when next_tool is not None.

Looking at the decide_next_action function:

```python
# Priority 3: Consistency rule - if next_tool exists, action must be continue
if next_tool is not None:
    return "continue"
```

This means that if next_tool is not None, next_action should be "continue". But we're seeing next_action='stop' with next_tool='httpx_basic' or next_tool='ssh-enum', which violates the consistency rule.

The root cause is that the decide_next_action function is not being called with the correct parameters, or there's a bug in the implementation.

Let's look at the call to decide_next_action in calculate_risk_v21:

```python
next_action = decide_next_action(
    base_risk_score=base_risk_score,
    adjusted_risk_score=adjusted_risk_score,
    confidence_score=confidence_score,
    severity=severity,
    next_tool=next_tool,  # This should be passed to decide_next_action
    waf_detected=waf_detected,
    tool_blocked=tool_blocked,
    tool_timeout=tool_timeout,
    kev_detected=kev,
    max_epss=epss,
    cvss=cvss,
)
```

The issue is that the decide_next_action function should be returning "continue" when next_tool is not None, but it's not doing so. Let's check if the parameters are being passed correctly.

Looking at the decide_next_action function again:

```python
# Priority 3: Consistency rule - if next_tool exists, action must be continue
if next_tool is not None:
    return "continue"
```

This means that if next_tool is not None, the function should return "continue". But we're seeing next_action='stop' with next_tool='httpx_basic' or next_tool='ssh-enum', which violates the consistency rule.

The root cause is that the decide_next_action function is not being called correctly, or there's a bug in the implementation.

Let's check if the issue is in the order of operations. Looking at the decide_next_action function:

```python
def decide_next_action(
    *,
    base_risk_score: float,
    adjusted_risk_score: float,
    confidence_score: float,
    severity: str,
    next_tool: str | None,
    waf_detected: bool,
    tool_blocked: bool,
    tool_timeout: bool,
    kev_detected: bool,
    max_epss: float | None,
    cvss: float | None,
) -> str:
    # Priority 1: KEV or CVSS >= 9.0
    if kev_detected:
        return "remediate"
    
    if cvss is not None and cvss >= 9.0:
        return "remediate"
    
    # Priority 2: Verification required conditions
    if base_risk_score >= 6 and confidence_score < 0.5:
        return "verify"

    if waf_detected or tool_blocked or tool_timeout:
        if base_risk_score >= 6:
            return "verify"
    
    if max_epss is not None and max_epss >= 0.8:
        return "verify"

    if severity == "critical":
        return "verify"
    
    if severity == "high":
        return "verify"
    
    # Priority 3: Consistency rule - if next_tool exists, action must be continue
    if next_tool is not None:
        return "continue"
    
    # Priority 4: No tool available
    if severity == "low":
        return "stop"
    
    return "stop"
```

The issue is that the function should return "continue" when next_tool is not None, but it's not doing so. This means that one of the earlier conditions is being met and returning before it gets to the "continue" check.

Let's trace through the logic:

1. If kev_detected is True, return "remediate"
2. If cvss >= 9.0, return "remediate"
3. If base_risk_score >= 6 and confidence_score < 0.5, return "verify"
4. If waf_detected or tool_blocked or tool_timeout and base_risk_score >= 6, return "verify"
5. If max_epss >= 0.8, return "verify"
6. If severity == "critical", return "verify"
7. If severity == "high", return "verify"
8. If next_tool is not None, return "continue"
9. If severity == "low", return "stop"
10. Return "stop"

The issue is that the function is returning "stop" even when next_tool is not None. This means that one of the earlier conditions is being met, causing it to return "stop" before it gets to the "continue" check.

Looking at condition 9: "If severity == 'low', return 'stop'". This is the problem! If severity is "low", it returns "stop" even if next_tool is not None.

The fix is to change the order of operations so that the "continue" check happens before the "stop" check for low severity.

Let's look at the current order:
1. KEV or CVSS >= 9.0 => remediate
2. high risk verification => verify
3. next_tool is not None => continue
4. low severity => stop
5. default => stop

The issue is that condition 4 (low severity) is being checked before condition 3 (next_tool is not None). This is the bug.

The fix is to change the order so that the "continue" check happens before the "stop" check for low severity.

The correct order should be:
1. KEV or CVSS >= 9.0 => remediate
2. high risk verification => verify
3. next_tool is not None => continue
4. low severity => stop
5. default => stop

But wait, that's not right either. The issue is that if next_tool is not None, it should always return "continue" regardless of severity. Let's look at the actual logic again:

```python
# Priority 3: Consistency rule - if next_tool exists, action must be continue
if next_tool is not None:
    return "continue"
```

This means that if next_tool is not None, it should return "continue" regardless of other conditions. But we're seeing next_action='stop' with next_tool='httpx_basic' or next_tool='ssh-enum'.

This means that the decide_next_action function is not working correctly. The issue is in the implementation.

Let's trace through a specific example:

If we have:
- next_tool='httpx_basic' (not None)
- severity='low'

The function should return "continue" because next_tool is not None, but it's returning "stop" because of the low severity check.

The issue is that the low severity check is happening before the next_tool check.

Looking at the code:
```python
# Priority 4: No tool available
if severity == "low":
    return "stop"

return "stop"
```

This is the bug! The function is checking for "low severity" and returning "stop" even when next_tool is not None.

The fix is to change the order of operations in the decide_next_action function so that the next_tool check happens before the low severity check.
