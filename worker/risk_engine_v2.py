"""Risk Engine v2.1.

Two-stage scoring:

1. base_risk_score
   - service exposure
   - CVSS
   - EPSS
   - KEV

2. adjusted_risk_score
   - positive tool evidence
   - negative tool evidence
   - learning feedback
   - runtime status

Important rule:
WAF / timeout / blocked should mainly reduce confidence_score,
not erase the underlying base risk.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RiskV21Result:
    target_id: int
    open_port_id: int | None

    base_risk_score: float
    adjusted_risk_score: float
    risk_score: float
    confidence_score: float

    learning_adjustment: float
    runtime_adjustment: float
    evidence_adjustment: float

    waf_detected: bool
    tool_blocked: bool
    tool_timeout: bool

    severity: str
    next_action: str
    next_tool: str | None

    reasoning: list[str]


HTTP_PORTS = {80, 443, 8000, 8080, 8443}


def clamp(value: float, minimum: float = 0.0, maximum: float = 10.0) -> float:
    return max(minimum, min(value, maximum))


def clamp_confidence(value: float) -> float:
    return max(0.0, min(value, 1.0))


def severity_from_score(score: float) -> str:
    if score >= 8:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def calculate_base_risk(
    *,
    service: str | None,
    port: int | None,
    cvss: float | None,
    epss: float | None,
    kev: bool,
) -> tuple[float, list[str]]:
    score = 0.0
    reasoning: list[str] = []

    service_name = (service or "").lower()

    if service_name in {"http", "https", "http-alt", "ssl/http"} or port in HTTP_PORTS:
        score += 2.0
        reasoning.append("HTTP-like exposed service adds base risk 2.0")
    elif service_name == "ssh" or port == 22:
        score += 1.5
        reasoning.append("SSH exposed service adds base risk 1.5")
    elif service_name in {"mysql", "mariadb"} or port == 3306:
        score += 2.0
        reasoning.append("Database exposed service adds base risk 2.0")
    else:
        score += 1.0
        reasoning.append("Generic open service adds base risk 1.0")

    if cvss is not None:
        cvss_score = float(cvss)
        score += min(cvss_score, 10.0) * 0.35
        reasoning.append(f"CVSS {cvss_score} contributes {min(cvss_score, 10.0) * 0.35:.2f}")

    if epss is not None:
        epss_score = float(epss)
        score += min(max(epss_score, 0.0), 1.0) * 2.0
        reasoning.append(f"EPSS {epss_score:.4f} contributes {min(max(epss_score, 0.0), 1.0) * 2.0:.2f}")

    if kev:
        score += 2.5
        reasoning.append("KEV detected adds base risk 2.5")

    return round(clamp(score), 2), reasoning


def detect_runtime_signals(parsed_output: dict[str, Any], raw_output: str = "") -> tuple[bool, bool, bool, list[str]]:
    text = f"{parsed_output} {raw_output}".lower()

    waf_keywords = [
        "waf",
        "cloudflare",
        "akamai",
        "imperva",
        "blocked",
        "access denied",
        "forbidden",
        "captcha",
    ]

    timeout_keywords = [
        "timeout",
        "timed out",
        "context deadline exceeded",
        "command timeout",
    ]

    blocked_keywords = [
        "403",
        "forbidden",
        "blocked",
        "rate limit",
        "too many requests",
        "connection reset",
    ]

    waf_detected = any(k in text for k in waf_keywords)
    tool_timeout = any(k in text for k in timeout_keywords)
    tool_blocked = any(k in text for k in blocked_keywords) or waf_detected

    reasoning: list[str] = []

    if waf_detected:
        reasoning.append("WAF-like signal detected")
    if tool_timeout:
        reasoning.append("Tool timeout detected")
    if tool_blocked:
        reasoning.append("Tool blocked / restricted signal detected")

    return waf_detected, tool_blocked, tool_timeout, reasoning


def calculate_runtime_adjustment(
    *,
    waf_detected: bool,
    tool_blocked: bool,
    tool_timeout: bool,
) -> tuple[float, float, list[str]]:
    """
    Returns:
    - runtime_adjustment for risk
    - confidence_multiplier

    Runtime failures should not strongly reduce risk.
    They mostly reduce confidence.
    """

    risk_adjustment = 0.0
    confidence_multiplier = 1.0
    reasoning: list[str] = []

    if waf_detected:
        confidence_multiplier *= 0.70
        reasoning.append("WAF reduces confidence multiplier to 0.70")

    if tool_blocked:
        confidence_multiplier *= 0.75
        reasoning.append("Tool blocked reduces confidence multiplier by 0.75")

    if tool_timeout:
        confidence_multiplier *= 0.65
        reasoning.append("Timeout reduces confidence multiplier by 0.65")

    return risk_adjustment, confidence_multiplier, reasoning


def calculate_evidence_adjustment(
    *,
    tool_name: str,
    parsed_output: dict[str, Any],
) -> tuple[float, list[str]]:
    adjustment = 0.0
    reasoning: list[str] = []

    finding_count = int(parsed_output.get("finding_count") or 0)

    if tool_name == "nuclei_safe":
        if finding_count > 0:
            adjustment += min(2.5, finding_count * 0.8)
            reasoning.append(f"nuclei finding_count={finding_count} increases risk")
        else:
            adjustment -= 0.3
            reasoning.append("nuclei found no finding; small risk reduction only")

    elif tool_name == "httpx_basic":
        status_code = parsed_output.get("status_code")

        if isinstance(status_code, int):
            if status_code >= 500:
                adjustment += 0.7
                reasoning.append(f"httpx status_code={status_code} increases risk")
            elif status_code in {401, 403}:
                adjustment += 0.2
                reasoning.append(f"httpx status_code={status_code} indicates protected surface")
            elif 200 <= status_code < 400:
                adjustment += 0.3
                reasoning.append(f"httpx status_code={status_code} confirms reachable HTTP surface")

    elif tool_name == "dirb_safe":
        found_paths = int(parsed_output.get("found_paths") or parsed_output.get("path_count") or 0)

        if found_paths > 0:
            adjustment += min(1.5, found_paths * 0.2)
            reasoning.append(f"dirb found_paths={found_paths} increases risk")
        else:
            adjustment -= 0.2
            reasoning.append("dirb found no paths; small risk reduction only")

    return round(adjustment, 2), reasoning


def calculate_learning_adjustment(
    learning_feedback: dict[str, Any] | None,
) -> tuple[float, list[str]]:
    if not learning_feedback:
        return 0.0, ["No learning feedback available"]

    success_rate = learning_feedback.get("success_rate")
    false_positive_rate = learning_feedback.get("false_positive_rate")

    adjustment = 0.0
    reasoning: list[str] = []

    if success_rate is not None:
        sr = float(success_rate)
        if sr > 1:
            sr = sr / 100

        if sr >= 0.75:
            adjustment += 0.4
            reasoning.append(f"Learning success_rate={sr:.2f} increases risk 0.4")
        elif sr <= 0.25:
            adjustment -= 0.4
            reasoning.append(f"Learning success_rate={sr:.2f} decreases risk 0.4")

    if false_positive_rate is not None:
        fp = float(false_positive_rate)
        if fp > 1:
            fp = fp / 100

        if fp >= 0.5:
            adjustment -= 0.5
            reasoning.append(f"Learning false_positive_rate={fp:.2f} decreases risk 0.5")

    return round(adjustment, 2), reasoning


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


def calculate_risk_v21(
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
    base_risk_score, r1 = calculate_base_risk(
        service=service,
        port=port,
        cvss=cvss,
        epss=epss,
        kev=kev,
    )

    waf_detected, tool_blocked, tool_timeout, r2 = detect_runtime_signals(
        parsed_output=parsed_output,
        raw_output=raw_output,
    )

    runtime_adjustment, confidence_multiplier, r3 = calculate_runtime_adjustment(
        waf_detected=waf_detected,
        tool_blocked=tool_blocked,
        tool_timeout=tool_timeout,
    )

    evidence_adjustment, r4 = calculate_evidence_adjustment(
        tool_name=tool_name,
        parsed_output=parsed_output,
    )

    learning_adjustment, r5 = calculate_learning_adjustment(learning_feedback)

    adjusted_risk_score = round(
        clamp(
            base_risk_score
            + runtime_adjustment
            + evidence_adjustment
            + learning_adjustment
        ),
        2,
    )

    confidence_score = round(
        clamp_confidence(base_confidence * confidence_multiplier),
        4,
    )

    severity = severity_from_score(adjusted_risk_score)

    next_tool = select_next_tool(
        service=service,
        port=port,
        adjusted_risk_score=adjusted_risk_score,
    )

    next_action = decide_next_action(
        base_risk_score=base_risk_score,
        adjusted_risk_score=adjusted_risk_score,
        confidence_score=confidence_score,
        severity=severity,
        next_tool=next_tool,
        waf_detected=waf_detected,
        tool_blocked=tool_blocked,
        tool_timeout=tool_timeout,
        kev_detected=kev,
        max_epss=epss,
        cvss=cvss,
    )

    reasoning = [
        *r1,
        *r2,
        *r3,
        *r4,
        *r5,
        f"base_risk_score={base_risk_score}",
        f"adjusted_risk_score={adjusted_risk_score}",
        f"confidence_score={confidence_score}",
        f"severity={severity}",
        f"next_action={next_action}",
        f"next_tool={next_tool}",
    ]

    return RiskV21Result(
        target_id=target_id,
        open_port_id=open_port_id,
        base_risk_score=base_risk_score,
        adjusted_risk_score=adjusted_risk_score,
        risk_score=adjusted_risk_score,
        confidence_score=confidence_score,
        learning_adjustment=learning_adjustment,
        runtime_adjustment=runtime_adjustment,
        evidence_adjustment=evidence_adjustment,
        waf_detected=waf_detected,
        tool_blocked=tool_blocked,
        tool_timeout=tool_timeout,
        severity=severity,
        next_action=next_action,
        next_tool=next_tool,
        reasoning=reasoning,
    )